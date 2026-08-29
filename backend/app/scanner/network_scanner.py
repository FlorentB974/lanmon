import asyncio
import socket
import struct
import fcntl
import json
from typing import Optional, List
from datetime import datetime, timezone

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
from datetime import timedelta


class ScanInProgressError(RuntimeError):
    """Raised when a second scan is requested while one is already running."""


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
        self._scan_lock = asyncio.Lock()
        self._websocket_callbacks = []
        
        # Deep scan optimization settings
        self.deep_scan_interval_hours = settings.DEEP_SCAN_PERIODIC_REFRESH_DAYS * 24
        self.recent_update_threshold_hours = settings.DEEP_SCAN_COMPLETE_INFO_SKIP_HOURS

    @property
    def is_scanning(self) -> bool:
        """Whether an ARP/deep scan is currently holding the scanner lock."""
        return self._scan_lock.locked()

    @staticmethod
    def _normalise_mac(mac: Optional[str]) -> str:
        return (mac or "").strip().lower().replace("-", ":")

    @classmethod
    def _is_private_mac(cls, mac: Optional[str]) -> bool:
        """Return True for locally administered/private Wi-Fi MAC addresses."""
        try:
            first_octet = int(cls._normalise_mac(mac).split(":")[0], 16)
            return bool(first_octet & 0x02)
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _mac_aliases(device: Device) -> list[str]:
        try:
            aliases = json.loads(device.mac_aliases or "[]")
            if isinstance(aliases, list):
                return [str(alias).lower() for alias in aliases]
        except (TypeError, ValueError):
            pass
        return []

    def _device_lookup(self, devices: list[Device]) -> dict[str, Device]:
        """Index current and historical MACs to the same logical device."""
        lookup: dict[str, Device] = {}
        for device in devices:
            lookup[self._normalise_mac(device.mac_address)] = device
            for alias in self._mac_aliases(device):
                lookup[alias] = device
        return lookup

    def _find_rotating_mac_match(
        self,
        discovered: DiscoveredDevice,
        enhanced: Optional[EnhancedDeviceInfo],
        existing_devices: list[Device],
        used_device_ids: set[int],
    ) -> Optional[Device]:
        """Match a private MAC to a previous row using multiple stable signals.

        A locally administered MAC is not enough on its own: the same address
        can be used by unrelated devices. The IP plus a hostname/model signal,
        or a recently-seen private MAC on the same IP, gives us a useful and
        conservative match without merging ordinary DHCP changes.
        """
        if not self._is_private_mac(discovered.mac_address):
            return None

        discovered_hostname = (
            enhanced.primary_hostname if enhanced and enhanced.primary_hostname else discovered.hostname
        )
        discovered_values = {
            "hostname": discovered_hostname,
            "friendly_name": enhanced.hostnames[0] if enhanced and enhanced.hostnames else None,
            "model": enhanced.model if enhanced else None,
            "manufacturer": enhanced.manufacturer if enhanced else None,
            "vendor": (enhanced.vendor if enhanced and enhanced.vendor else discovered.vendor),
            "device_type": enhanced.detected_type if enhanced else None,
        }

        def clean(value: Optional[str]) -> Optional[str]:
            if not value:
                return None
            value = value.strip().lower()
            if value.endswith(".local"):
                return None
            return value

        candidates: list[tuple[int, Device]] = []
        for device in existing_devices:
            if device.id in used_device_ids:
                continue

            score = 0
            if device.ip_address and device.ip_address == discovered.ip_address:
                score += 3

            for field, weight in (("hostname", 5), ("friendly_name", 5), ("model", 3), ("manufacturer", 2), ("vendor", 1), ("device_type", 1)):
                incoming = clean(discovered_values[field])
                current = clean(getattr(device, field, None))
                if incoming and current and incoming == current:
                    score += weight

            has_private_history = self._is_private_mac(device.mac_address) or any(
                self._is_private_mac(alias) for alias in self._mac_aliases(device)
            )
            same_ip = device.ip_address == discovered.ip_address

            # Same IP + a private historical MAC is the common Apple/Android
            # rotation case when discovery has no hostname. It is only used
            # when there is a single best candidate.
            if same_ip and has_private_history:
                score += 2

            if score >= 5:
                candidates.append((score, device))

        if not candidates:
            return None

        candidates.sort(key=lambda item: item[0], reverse=True)
        _best_score, best_device = candidates[0]
        if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
            return None
        return best_device
    
    def _should_deep_scan_device(self, device: Device) -> bool:
        """
        Determine if a device needs a deep scan based on information completeness.
        
        Criteria for skipping deep scan:
        - Device is marked as known (is_known=True) - user has acknowledged it
        - Device has complete information (hostname, vendor/manufacturer, device_type, model, services, open_ports)
        - Device was updated recently (within last 24 hours)
        
        Always deep scan:
        - New/unknown devices (is_known=False)
        - Devices with incomplete information
        - Devices not scanned in the last 7 days (periodic refresh)
        """
        # Always scan new/unknown devices
        if not device.is_known:
            return True
        
        # If device is known (marked by user), treat it as complete and check timing
        # This allows users to skip deep scans on devices they've acknowledged
        if device.updated_at:
            now = datetime.now(timezone.utc)
            
            # Ensure device.updated_at is timezone-aware for comparison
            updated_at = device.updated_at
            if updated_at.tzinfo is None:
                # If naive datetime, assume it's UTC
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            
            time_since_update = now - updated_at
            
            # Skip scan if updated recently (within threshold)
            if time_since_update < timedelta(hours=self.recent_update_threshold_hours):
                return False
            
            # Force deep scan if not scanned in a long time (periodic refresh)
            if time_since_update > timedelta(hours=self.deep_scan_interval_hours):
                return True
        
        # For known devices without recent updates, still check if info is complete
        has_name = bool(device.hostname or device.friendly_name)
        has_vendor = bool(device.vendor or device.manufacturer)
        has_type = bool(device.device_type)
        has_model = bool(device.model)
        has_services = bool(device.services)
        has_ports = bool(device.open_ports)
        
        is_complete = has_name and has_vendor and has_type and has_model and has_services and has_ports
        
        # If device is incomplete, scan it
        if not is_complete:
            return True
        
        # Default: skip deep scan for known devices with complete info
        return False
    
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
        """Run one scan without allowing background/manual scans to overlap."""
        if self._scan_lock.locked():
            raise ScanInProgressError("A network scan is already in progress")

        await self._scan_lock.acquire()
        try:
            return await self._perform_scan(subnet=subnet, deep_scan=deep_scan)
        finally:
            self._scan_lock.release()

    async def _perform_scan(self, subnet: Optional[str] = None, deep_scan: bool = True) -> dict:
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
                started_at=datetime.now(timezone.utc)
            )
            session.add(scan_session)
            await session.flush()
            # Do not keep a write transaction open while ARP/mDNS/HTTP probes
            # run. That used to make edits from the drawer wait behind a scan.
            await session.commit()
            
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
                
                # Get all existing devices to determine which need deep scanning
                result = await session.execute(select(Device))
                existing_device_list = result.scalars().all()
                existing_devices = {self._normalise_mac(d.mac_address): d for d in existing_device_list}
                device_lookup = self._device_lookup(existing_device_list)
                
                # Determine which devices need deep scanning
                devices_needing_deep_scan = []
                if deep_scan and discovered:
                    for disc_device in discovered:
                        existing_device = device_lookup.get(self._normalise_mac(disc_device.mac_address))
                        if existing_device is None or self._should_deep_scan_device(existing_device):
                            devices_needing_deep_scan.append(disc_device)
                    
                    if devices_needing_deep_scan:
                        print(f"🔍 Performing deep scan on {len(devices_needing_deep_scan)}/{len(discovered)} devices...")
                        skipped_count = len(discovered) - len(devices_needing_deep_scan)
                        if skipped_count > 0:
                            print(f"   ⏭️  Skipped {skipped_count} devices with complete information")
                    else:
                        print(f"✨ All {len(discovered)} devices have complete information - skipping deep scan")

                # Release the read transaction while network probes are in
                # flight. A fresh snapshot is loaded before applying changes.
                await session.rollback()
                
                # Perform enhanced device info gathering for selected devices
                enhanced_info_map = {}
                if devices_needing_deep_scan:
                    try:
                        devices_to_scan = [
                            {'ip': d.ip_address, 'mac': d.mac_address}
                            for d in devices_needing_deep_scan
                        ]
                        print(f"📋 Deep scan will check {len(devices_to_scan)} devices: {[d['ip'] for d in devices_to_scan]}")
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
                
                # Refresh existing_devices in case we need the latest data
                result = await session.execute(select(Device))
                existing_device_list = result.scalars().all()
                existing_devices = {self._normalise_mac(d.mac_address): d for d in existing_device_list}
                device_lookup = self._device_lookup(existing_device_list)

                # Resolve all discoveries before marking missing devices
                # offline. A newly rotated private MAC should count as the
                # same device for this scan rather than as a disconnect/new
                # pair.
                matched_devices: dict[str, Device] = {}
                matched_device_ids: set[int] = set()
                for disc_device in discovered:
                    observed_mac = self._normalise_mac(disc_device.mac_address)
                    device = device_lookup.get(observed_mac)
                    if device is None:
                        device = self._find_rotating_mac_match(
                            disc_device,
                            enhanced_info_map.get(disc_device.ip_address),
                            existing_device_list,
                            matched_device_ids,
                        )
                    if device is not None:
                        matched_devices[observed_mac] = device
                        matched_device_ids.add(device.id)
                
                # Track statistics
                devices_found = len(discovered)
                devices_online = 0
                devices_new = 0
                
                # Handle devices not found in this scan - use grace period
                current_macs = {d.mac_address for d in discovered}
                devices_to_verify = []
                
                for mac, device in existing_devices.items():
                    if device.id in matched_device_ids:
                        device.missed_scans = 0
                        continue
                    if mac not in current_macs:
                        if device.is_online:
                            # Device was online but not found in this scan
                            # Increment missed_scans counter
                            device.missed_scans = (device.missed_scans or 0) + 1
                            device.updated_at = datetime.now(timezone.utc)
                            
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
                        device.updated_at = datetime.now(timezone.utc)
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
                    
                    observed_mac = self._normalise_mac(disc_device.mac_address)
                    device = matched_devices.get(observed_mac) or device_lookup.get(observed_mac)
                    if device is not None:
                        # Update existing device
                        old_ip = device.ip_address
                        was_online = device.is_online

                        # Preserve the old address as an alias before moving
                        # the current address to the newly observed private
                        # MAC. This keeps future scans attached to one row.
                        old_mac = self._normalise_mac(device.mac_address)
                        if old_mac != observed_mac:
                            aliases = self._mac_aliases(device)
                            if old_mac and old_mac not in aliases:
                                aliases.append(old_mac)
                            device.mac_aliases = json.dumps(aliases)
                            device.mac_address = observed_mac
                        
                        device.ip_address = disc_device.ip_address
                        device.is_online = True
                        device.missed_scans = 0  # Reset missed scans counter
                        device.last_seen = datetime.now(timezone.utc)
                        device.updated_at = datetime.now(timezone.utc)
                        
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
                            mac_address=observed_mac,
                            mac_aliases="[]",
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
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc)
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
                scan_session.completed_at = datetime.now(timezone.utc)
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
                scan_session.completed_at = datetime.now(timezone.utc)
                await session.commit()
                
                await self._notify_callbacks("scan_failed", {
                    "session_id": scan_session.id,
                    "error": str(e)
                })
                
                raise
