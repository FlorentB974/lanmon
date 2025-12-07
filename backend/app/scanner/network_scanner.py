import asyncio
import socket
import struct
import fcntl
from typing import Optional, List
from datetime import datetime

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

from .arp_scanner import ARPScanner, DiscoveredDevice
from .device_info import DeviceInfoScanner, EnhancedDeviceInfo
from ..db.models import Device, ScanEvent, ScanSession
from ..db.database import AsyncSessionLocal
from ..core.config import settings
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload


class NetworkScanner:
    """Main network scanner orchestrating device discovery and tracking."""
    
    def __init__(self, scan_interval: int = None):
        self.scan_interval = scan_interval or settings.SCAN_INTERVAL
        self.offline_grace_scans = settings.OFFLINE_GRACE_SCANS
        self.arp_scanner = ARPScanner(
            timeout=settings.SCAN_TIMEOUT, 
            retries=settings.SCAN_RETRIES
        )
        self.device_info_scanner = DeviceInfoScanner()
        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._websocket_callbacks = []
    
    def register_callback(self, callback):
        """Register a callback for scan updates."""
        self._websocket_callbacks.append(callback)
    
    def unregister_callback(self, callback):
        """Unregister a callback."""
        if callback in self._websocket_callbacks:
            self._websocket_callbacks.remove(callback)
    
    async def _notify_callbacks(self, event_type: str, data: dict):
        """Notify all registered callbacks."""
        for callback in self._websocket_callbacks:
            try:
                await callback(event_type, data)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def get_default_subnet(self) -> Optional[str]:
        """Get the default network subnet - from config or auto-detect."""
        # First, check if DEFAULT_SUBNET is set in config/env
        if settings.DEFAULT_SUBNET:
            print(f"Using configured subnet: {settings.DEFAULT_SUBNET}")
            return settings.DEFAULT_SUBNET
        
        # Auto-detect if not configured
        if NETIFACES_AVAILABLE:
            try:
                # Get default gateway interface
                gateways = netifaces.gateways()
                default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
                
                if default_gateway:
                    interface = default_gateway[1]
                    addrs = netifaces.ifaddresses(interface)
                    
                    if netifaces.AF_INET in addrs:
                        ipv4_info = addrs[netifaces.AF_INET][0]
                        ip = ipv4_info['addr']
                        netmask = ipv4_info['netmask']
                        
                        # Calculate network address
                        ip_parts = [int(x) for x in ip.split('.')]
                        mask_parts = [int(x) for x in netmask.split('.')]
                        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                        
                        # Count network bits
                        mask_bits = sum(bin(x).count('1') for x in mask_parts)
                        
                        network = '.'.join(str(x) for x in network_parts)
                        detected_subnet = f"{network}/{mask_bits}"
                        print(f"Auto-detected subnet: {detected_subnet}")
                        return detected_subnet
            except Exception as e:
                print(f"Error detecting subnet: {e}")
        
        # Fallback to common home network
        fallback = "192.168.1.0/24"
        print(f"Using fallback subnet: {fallback}")
        return fallback
    
    async def start_background_scanning(self):
        """Start background network scanning."""
        if self._running:
            return
        
        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())
    
    async def stop_background_scanning(self):
        """Stop background network scanning."""
        self._running = False
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
    
    async def _scan_loop(self):
        """Main scanning loop."""
        while self._running:
            try:
                await self.perform_scan()
            except Exception as e:
                print(f"Scan error: {e}")
            
            await asyncio.sleep(self.scan_interval)
    
    async def perform_scan(self, subnet: Optional[str] = None, deep_scan: bool = True) -> dict:
        """
        Perform a network scan and update the database.
        
        Args:
            subnet: Network subnet to scan (auto-detected if None)
            deep_scan: If True, perform enhanced device info gathering
        
        Returns:
            Scan results summary
        """
        if subnet is None:
            subnet = self.get_default_subnet()
        
        async with AsyncSessionLocal() as session:
            # Create scan session
            scan_session = ScanSession(
                subnet=subnet,
                scan_method="arp+enhanced" if deep_scan else "arp",
                started_at=datetime.utcnow()
            )
            session.add(scan_session)
            await session.flush()
            
            try:
                # Notify scan started
                await self._notify_callbacks("scan_started", {
                    "session_id": scan_session.id,
                    "subnet": subnet
                })
                
                # Perform ARP scan
                discovered = await self.arp_scanner.scan_subnet(subnet)
                
                # DEBUG: Log discovered IPs
                print(f"📡 ARP scanner discovered {len(discovered)} devices:")
                for d in discovered:
                    print(f"   - {d.ip_address} ({d.mac_address})")
                
                # Perform enhanced device info gathering for all discovered devices
                enhanced_info_map = {}
                if deep_scan and discovered:
                    print(f"🔍 Performing deep scan on {len(discovered)} devices...")
                    try:
                        devices_to_scan = [
                            {'ip': d.ip_address, 'mac': d.mac_address}
                            for d in discovered
                        ]
                        # Run deep scan with a global timeout to avoid blocking the main scan loop
                        enhanced_results = await asyncio.wait_for(
                            self.device_info_scanner.scan_network_enhanced(devices_to_scan),
                            timeout=max(10, self.scan_interval // 2)
                        )
                        
                        for result in enhanced_results:
                            if isinstance(result, EnhancedDeviceInfo):
                                enhanced_info_map[result.ip_address] = result
                                print(f"  ✓ {result.ip_address}: {result.primary_hostname or 'unknown'} - {result.detected_type or 'unknown type'}")
                    except asyncio.TimeoutError:
                        print("⚠️ Deep scan timed out; proceeding with available data")
                    except Exception as e:
                        print(f"Enhanced scan error: {e}")
                
                # Get all existing devices
                result = await session.execute(select(Device))
                existing_devices = {d.mac_address: d for d in result.scalars().all()}
                
                # Track statistics
                devices_found = len(discovered)
                devices_online = 0
                devices_new = 0
                
                # Handle devices not found in this scan - use grace period
                current_macs = {d.mac_address for d in discovered}
                devices_to_verify = []
                
                for mac, device in existing_devices.items():
                    if mac not in current_macs:
                        if device.is_online:
                            # Device was online but not found in this scan
                            # Increment missed_scans counter
                            device.missed_scans = (device.missed_scans or 0) + 1
                            device.updated_at = datetime.utcnow()
                            
                            if device.missed_scans >= self.offline_grace_scans:
                                # Device has been missing for multiple scans, verify before marking offline
                                devices_to_verify.append(device)
                            else:
                                print(f"  ⚠️ {device.ip_address}: {device.hostname or device.mac_address} - not seen ({device.missed_scans}/{self.offline_grace_scans})")
                    else:
                        # Device was found, reset missed_scans counter
                        device.missed_scans = 0
                
                # Verify devices that have exceeded grace period before marking offline
                for device in devices_to_verify:
                    print(f"  🔄 Verifying {device.ip_address} ({device.hostname or device.mac_address})...")
                    is_still_online = await self.arp_scanner.verify_device_online(
                        device.ip_address, 
                        device.mac_address
                    )
                    
                    if is_still_online:
                        # Device responded to verification, reset counter
                        device.missed_scans = 0
                        print(f"  ✓ {device.ip_address}: {device.hostname or device.mac_address} - verified online")
                    else:
                        # Device is truly offline
                        device.is_online = False
                        device.missed_scans = 0
                        device.updated_at = datetime.utcnow()
                        print(f"  ✗ {device.ip_address}: {device.hostname or device.mac_address} - offline")
                        
                        # Create disconnection event
                        event = ScanEvent(
                            device_id=device.id,
                            event_type="disconnected",
                            ip_address=device.ip_address,
                            scan_method="arp"
                        )
                        session.add(event)
                        
                        await self._notify_callbacks("device_disconnected", {
                            "device_id": device.id,
                            "mac_address": device.mac_address,
                            "hostname": device.hostname or device.custom_name
                        })
                
                # Process discovered devices
                for disc_device in discovered:
                    devices_online += 1
                    
                    # Get enhanced info for this device
                    enhanced = enhanced_info_map.get(disc_device.ip_address)
                    
                    # Determine best hostname
                    hostname = disc_device.hostname
                    if enhanced and enhanced.primary_hostname:
                        hostname = enhanced.primary_hostname
                    
                    # Determine best vendor
                    vendor = disc_device.vendor
                    if enhanced and enhanced.manufacturer:
                        vendor = enhanced.manufacturer
                    elif enhanced and enhanced.vendor:
                        vendor = enhanced.vendor
                    
                    # Extract manufacturer (separate from vendor)
                    manufacturer = None
                    if enhanced and enhanced.manufacturer:
                        manufacturer = enhanced.manufacturer
                    
                    # Extract model
                    model = None
                    if enhanced and enhanced.model:
                        model = enhanced.model
                    
                    # Extract friendly name (from Avahi)
                    friendly_name = None
                    if enhanced and hasattr(enhanced, 'friendly_name'):
                        friendly_name = enhanced.friendly_name
                    elif enhanced and enhanced.hostnames:
                        # Use the first hostname if no friendly name
                        friendly_name = enhanced.hostnames[0] if enhanced.hostnames else None
                    
                    # Determine device type
                    device_type = None
                    if enhanced:
                        device_type = enhanced.detected_type
                    
                    # Get open ports as JSON string
                    open_ports_str = None
                    if enhanced and enhanced.open_ports:
                        import json
                        open_ports_str = json.dumps(enhanced.open_ports)
                    
                    # Get services as JSON string
                    services_str = None
                    if enhanced and enhanced.mdns_services:
                        import json
                        # Keep only first 10 services to avoid huge strings
                        services_str = json.dumps(enhanced.mdns_services[:10])
                    
                    if disc_device.mac_address in existing_devices:
                        # Update existing device
                        device = existing_devices[disc_device.mac_address]
                        old_ip = device.ip_address
                        was_online = device.is_online
                        
                        device.ip_address = disc_device.ip_address
                        device.is_online = True
                        device.missed_scans = 0  # Reset missed scans counter
                        device.last_seen = datetime.utcnow()
                        device.updated_at = datetime.utcnow()
                        
                        # Update hostname if we found a better one
                        if hostname and (not device.hostname or device.hostname.endswith('.local')):
                            device.hostname = hostname
                        
                        # Update vendor if missing or if we have manufacturer info
                        if vendor and not device.vendor:
                            device.vendor = vendor
                        
                        # Update manufacturer
                        if manufacturer:
                            device.manufacturer = manufacturer
                        
                        # Update model
                        if model:
                            device.model = model
                        
                        # Update friendly name if we found one
                        if friendly_name and not device.friendly_name:
                            device.friendly_name = friendly_name
                        
                        # Update device type if we detected one
                        if device_type and not device.device_type:
                            device.device_type = device_type
                        
                        # Update open ports
                        if open_ports_str:
                            device.open_ports = open_ports_str
                        
                        # Update services
                        if services_str:
                            device.services = services_str
                        
                        # Create events
                        if not was_online:
                            event = ScanEvent(
                                device_id=device.id,
                                event_type="connected",
                                ip_address=disc_device.ip_address,
                                response_time=disc_device.response_time,
                                scan_method=disc_device.scan_method
                            )
                            session.add(event)
                            
                            await self._notify_callbacks("device_connected", {
                                "device_id": device.id,
                                "mac_address": device.mac_address,
                                "ip_address": device.ip_address,
                                "hostname": device.hostname or device.custom_name
                            })
                        
                        if old_ip and old_ip != disc_device.ip_address:
                            event = ScanEvent(
                                device_id=device.id,
                                event_type="ip_changed",
                                ip_address=disc_device.ip_address,
                                old_ip_address=old_ip,
                                scan_method=disc_device.scan_method
                            )
                            session.add(event)
                            
                            await self._notify_callbacks("device_ip_changed", {
                                "device_id": device.id,
                                "mac_address": device.mac_address,
                                "old_ip": old_ip,
                                "new_ip": disc_device.ip_address
                            })
                    else:
                        # New device discovered
                        devices_new += 1
                        
                        device = Device(
                            mac_address=disc_device.mac_address,
                            ip_address=disc_device.ip_address,
                            hostname=hostname,
                            vendor=vendor,
                            manufacturer=manufacturer,
                            model=model,
                            friendly_name=friendly_name,
                            device_type=device_type,
                            open_ports=open_ports_str,
                            services=services_str,
                            is_online=True,
                            is_known=False,  # New device starts as unknown
                            missed_scans=0,
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow()
                        )
                        session.add(device)
                        await session.flush()
                        
                        # Create discovery event
                        event = ScanEvent(
                            device_id=device.id,
                            event_type="connected",
                            ip_address=disc_device.ip_address,
                            response_time=disc_device.response_time,
                            scan_method=disc_device.scan_method
                        )
                        session.add(event)
                        
                        await self._notify_callbacks("device_new", {
                            "device_id": device.id,
                            "mac_address": device.mac_address,
                            "ip_address": device.ip_address,
                            "hostname": device.hostname,
                            "vendor": device.vendor
                        })
                
                # Update scan session
                scan_session.completed_at = datetime.utcnow()
                scan_session.status = "completed"
                scan_session.devices_found = devices_found
                scan_session.devices_online = devices_online
                scan_session.devices_new = devices_new
                
                await session.commit()
                
                result = {
                    "session_id": scan_session.id,
                    "status": "completed",
                    "devices_found": devices_found,
                    "devices_online": devices_online,
                    "devices_new": devices_new,
                    "subnet": subnet
                }
                
                await self._notify_callbacks("scan_completed", result)
                
                return result
                
            except Exception as e:
                scan_session.status = "failed"
                scan_session.error_message = str(e)
                scan_session.completed_at = datetime.utcnow()
                await session.commit()
                
                await self._notify_callbacks("scan_failed", {
                    "session_id": scan_session.id,
                    "error": str(e)
                })
                
                raise
