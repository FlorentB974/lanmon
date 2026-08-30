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
from .dhcp_leases import load_dhcp_leases
from .fingerprint import FingerprintInput, fingerprint_classifier
from ..db.models import Device, ScanEvent, ScanSession
from ..db.database import AsyncSessionLocal
from ..core.config import settings
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from datetime import timedelta


class ScanInProgressError(RuntimeError):
    """Raised when a second scan is requested while one is already running."""


class DeviceOfflineError(RuntimeError):
    """Raised when a targeted identification cannot safely reach its device."""


class DeviceIdentityMismatchError(RuntimeError):
    """Raised when DHCP reuse has moved a different MAC onto the stored IP."""


class IdentificationCooldownError(RuntimeError):
    """Raised when the same device is identified again too quickly."""


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
        self.incomplete_scan_interval_hours = settings.DEEP_SCAN_INCOMPLETE_REFRESH_HOURS
        self.identify_cooldown_seconds = settings.IDENTIFY_COOLDOWN_SECONDS

    @property
    def is_scanning(self) -> bool:
        """Whether an ARP/deep scan is currently holding the scanner lock."""
        return self._scan_lock.locked()

    @staticmethod
    def _normalise_mac(mac: Optional[str]) -> str:
        """Return a stable colon-separated representation of a MAC address."""
        value = (mac or "").strip().lower().replace("-", ":").replace(".", "")
        compact = value.replace(":", "")
        if len(compact) == 12 and all(character in "0123456789abcdef" for character in compact):
            return ":".join(compact[index:index + 2] for index in range(0, 12, 2))
        return value

    @classmethod
    def _is_private_mac(cls, mac: Optional[str]) -> bool:
        """Return True for locally administered/private Wi-Fi MAC addresses."""
        try:
            parts = cls._normalise_mac(mac).split(":")
            if len(parts) != 6:
                return False
            first_octet = int(parts[0], 16)
            # Exclude multicast addresses; ARP discoveries should be unicast.
            return (first_octet & 0x03) == 0x02
        except (ValueError, IndexError):
            return False

    @classmethod
    def _mac_aliases(cls, device: Device) -> list[str]:
        try:
            aliases = json.loads(device.mac_aliases or "[]")
            if isinstance(aliases, list):
                normalised = []
                for alias in aliases:
                    value = cls._normalise_mac(str(alias))
                    if value and value not in normalised:
                        normalised.append(value)
                return normalised
        except (TypeError, ValueError):
            pass
        return []

    def _device_lookup(self, devices: list[Device]) -> dict[str, Device]:
        """Index current and historical MACs to the same logical device."""
        lookup: dict[str, Device] = {}
        ambiguous: set[str] = set()
        for device in devices:
            addresses = [device.mac_address, *self._mac_aliases(device)]
            for address in addresses:
                normalised = self._normalise_mac(address)
                if not normalised or normalised in ambiguous:
                    continue
                previous = lookup.get(normalised)
                if previous is not None and previous.id != device.id:
                    # An alias collision is not safe to resolve automatically.
                    lookup.pop(normalised, None)
                    ambiguous.add(normalised)
                    continue
                lookup[normalised] = device
        return lookup

    def _find_rotating_mac_match(
        self,
        discovered: DiscoveredDevice,
        enhanced: Optional[EnhancedDeviceInfo],
        existing_devices: list[Device],
        used_device_ids: set[int],
        identity_hint: Optional[Device] = None,
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
            enhanced.primary_hostname if enhanced and enhanced.primary_hostname
            else discovered.hostname
            or (identity_hint.hostname if identity_hint else None)
        )
        discovered_values = {
            "hostname": discovered_hostname,
            "friendly_name": (
                enhanced.hostnames[0] if enhanced and enhanced.hostnames
                else (identity_hint.friendly_name if identity_hint else None)
            ),
            "model": (
                enhanced.model if enhanced and enhanced.model
                else (identity_hint.model if identity_hint else None)
            ),
            "manufacturer": (
                enhanced.manufacturer if enhanced and enhanced.manufacturer
                else (identity_hint.manufacturer if identity_hint else None)
            ),
            "vendor": (
                enhanced.vendor if enhanced and enhanced.vendor
                else discovered.vendor
                or (identity_hint.vendor if identity_hint else None)
            ),
            "device_type": (
                enhanced.detected_type if enhanced and enhanced.detected_type
                else (identity_hint.device_type if identity_hint else None)
            ),
        }

        def clean(value: Optional[str]) -> Optional[str]:
            if not value:
                return None
            value = value.strip().lower()
            if value.endswith(".local"):
                return None
            return value

        incoming_values = {
            field: clean(value) for field, value in discovered_values.items()
        }

        candidates: list[tuple[int, Device]] = []
        for device in existing_devices:
            if device.id in used_device_ids:
                continue

            score = 0
            same_ip = bool(device.ip_address and device.ip_address == discovered.ip_address)
            if same_ip:
                score += 3

            for field, weight in (("hostname", 5), ("friendly_name", 5), ("model", 3), ("manufacturer", 2), ("vendor", 1), ("device_type", 1)):
                incoming = incoming_values[field]
                current = clean(getattr(device, field, None))
                if incoming and current and incoming == current:
                    score += weight

            has_private_history = self._is_private_mac(device.mac_address) or any(
                self._is_private_mac(alias) for alias in self._mac_aliases(device)
            )
            # A known device that is still online at the same IP is the
            # strongest practical signal when the new randomized MAC has no
            # hostname or vendor. This handles the common first rotation from
            # a factory MAC, before any alias history exists.
            if same_ip and device.is_known and device.is_online:
                score += 4

            # Same IP + a private historical MAC is also useful when the
            # device has already rotated once. It is only used when there is
            # a single sufficiently strong candidate.
            if same_ip and has_private_history:
                score += 2

            if score >= 5:
                candidates.append((score, device))

        if not candidates:
            return None

        candidates.sort(key=lambda item: item[0], reverse=True)
        best_score, best_device = candidates[0]
        if len(candidates) > 1 and best_score - candidates[1][0] < 2:
            return None
        return best_device

    async def _merge_device_records(
        self,
        source: Device,
        target: Device,
        session,
    ) -> None:
        """Fold an older unknown private-MAC row into a known device row."""
        # Keep user annotations and any discovery data that the known row is
        # missing. The known row remains authoritative for conflicting values.
        for field in (
            "hostname", "vendor", "manufacturer", "device_type", "model",
            "friendly_name", "custom_name", "notes", "services", "discovery_info", "open_ports",
            "network_interface", "identification_data", "last_deep_scan_at",
        ):
            if not getattr(target, field, None) and getattr(source, field, None):
                setattr(target, field, getattr(source, field))

        target.is_favorite = bool(target.is_favorite or source.is_favorite)
        first_seen_values = [
            value for value in (target.first_seen, source.first_seen) if value is not None
        ]
        if first_seen_values:
            target.first_seen = min(first_seen_values)

        aliases = self._mac_aliases(target)
        target_mac = self._normalise_mac(target.mac_address)
        source_mac = self._normalise_mac(source.mac_address)
        for address in [target_mac, source_mac, *self._mac_aliases(source)]:
            if address and address not in aliases:
                aliases.append(address)
        target.mac_aliases = json.dumps(aliases)

        # Preserve the source row's event history under the durable device ID
        # before deleting the duplicate row.
        await session.execute(
            update(ScanEvent)
            .where(ScanEvent.device_id == source.id)
            .values(device_id=target.id)
        )
        await session.delete(source)

    @staticmethod
    def _serialise_discovery_info(enhanced: Optional[EnhancedDeviceInfo]) -> Optional[str]:
        """Keep the raw protocol results that do not fit legacy columns."""
        if enhanced is None:
            return None

        details = {
            "hostnames": enhanced.hostnames,
            "friendly_name": enhanced.friendly_name,
            "mdns_services": enhanced.mdns_services,
            "network_services": enhanced.services,
            "netbios_name": enhanced.netbios_name,
            "ssdp": enhanced.ssdp_info,
            "upnp": enhanced.upnp_info,
            "http": enhanced.http_info,
            "banners": enhanced.banners,
            "tls": enhanced.tls_info,
            "dhcp": enhanced.dhcp_info,
            "probes": enhanced.probe_status,
            "scan_profile": enhanced.scan_profile,
        }
        # Avoid storing an empty blob for hosts that answered no metadata
        # probes. This also preserves older, richer results on a transient
        # network failure.
        if not any(value for value in details.values()):
            return None
        return json.dumps(details, sort_keys=True)
    
    def _should_deep_scan_device(self, device: Device) -> bool:
        """Refresh incomplete profiles daily and useful profiles weekly."""
        if not device.last_deep_scan_at:
            return True

        scanned_at = device.last_deep_scan_at
        if scanned_at.tzinfo is None:
            scanned_at = scanned_at.replace(tzinfo=timezone.utc)
        profile = device.identification or {}
        is_complete = bool(
            profile.get("label") and profile.get("confidence") in {"medium", "high"}
        )
        refresh_hours = self.deep_scan_interval_hours if is_complete else self.incomplete_scan_interval_hours
        return datetime.now(timezone.utc) - scanned_at >= timedelta(hours=refresh_hours)

    @staticmethod
    def _parse_json_list(value: Optional[str]) -> list:
        try:
            parsed = json.loads(value or "[]")
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return []

    def _classify_device(
        self,
        enhanced: EnhancedDeviceInfo,
        *,
        vendor: Optional[str],
        existing: Optional[Device] = None,
    ) -> dict:
        """Build a typed, explainable identity from current and stored clues."""
        stored_services = self._parse_json_list(existing.services) if existing else []
        stored_ports = self._parse_json_list(existing.open_ports) if existing else []
        return fingerprint_classifier.classify(FingerprintInput(
            vendor=vendor or (existing.vendor if existing else None),
            manufacturer=enhanced.manufacturer or (existing.manufacturer if existing else None),
            model=enhanced.model or (existing.model if existing else None),
            friendly_name=enhanced.friendly_name or (existing.friendly_name if existing else None),
            hostnames=list(dict.fromkeys([
                *enhanced.hostnames,
                *([existing.hostname] if existing and existing.hostname else []),
            ])),
            services=list(dict.fromkeys([*enhanced.mdns_services, *enhanced.services, *stored_services])),
            open_ports=list(dict.fromkeys([*enhanced.open_ports, *stored_ports])),
            http_info=enhanced.http_info,
            upnp_info=enhanced.upnp_info,
            banners=enhanced.banners,
            dhcp_info=enhanced.dhcp_info,
            probes=enhanced.probe_status,
        ))

    @staticmethod
    def _should_store_identification(current: Optional[dict], candidate: dict, profile: str) -> bool:
        if profile != "light" or not current:
            return True
        return int(candidate.get("score") or 0) > int(current.get("score") or 0)

    @staticmethod
    def _merge_discovery_info(current: Optional[str], incoming: Optional[str]) -> Optional[str]:
        if not incoming:
            return current
        try:
            current_value = json.loads(current or "{}")
            incoming_value = json.loads(incoming)
            if not isinstance(current_value, dict) or not isinstance(incoming_value, dict):
                return incoming
            merged = dict(current_value)
            for key, value in incoming_value.items():
                if value not in (None, "", [], {}):
                    merged[key] = value
            return json.dumps(merged, sort_keys=True)
        except (TypeError, ValueError):
            return incoming
    
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

    async def identify_device(self, device_id: int) -> Device:
        """Run the bounded manual fingerprint profile for one verified host."""
        if self._scan_lock.locked():
            raise ScanInProgressError("A network scan or identification is already in progress")

        await self._scan_lock.acquire()
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Device).where(Device.id == device_id))
                device = result.scalar_one_or_none()
                if device is None:
                    raise LookupError("Device not found")
                if not device.is_online or not device.ip_address:
                    raise DeviceOfflineError("Only online devices can be identified")

                if device.last_deep_scan_at:
                    scanned_at = device.last_deep_scan_at
                    if scanned_at.tzinfo is None:
                        scanned_at = scanned_at.replace(tzinfo=timezone.utc)
                    elapsed = datetime.now(timezone.utc) - scanned_at
                    if elapsed < timedelta(seconds=self.identify_cooldown_seconds):
                        remaining = self.identify_cooldown_seconds - int(elapsed.total_seconds())
                        raise IdentificationCooldownError(
                            f"Please wait {max(1, remaining)} seconds before identifying this device again"
                        )

                device_ip = device.ip_address
                expected_macs = {
                    self._normalise_mac(device.mac_address),
                    *self._mac_aliases(device),
                }
                await session.rollback()

                observed_mac = await self.arp_scanner.resolve_mac(device_ip)
                if not observed_mac:
                    raise DeviceOfflineError("The device did not answer the ARP identity check")
                observed_mac = self._normalise_mac(observed_mac)
                if observed_mac not in expected_macs:
                    raise DeviceIdentityMismatchError(
                        "The stored IP now belongs to a different MAC address; run a network scan first"
                    )

                lease_result = load_dhcp_leases(settings.DHCP_LEASE_FILE, settings.DHCP_LEASE_FORMAT)
                lease = lease_result.by_mac().get(observed_mac)
                results = await self.device_info_scanner.scan_network_enhanced([{
                    "ip": device_ip,
                    "mac": observed_mac,
                    "profile": "identify",
                    "dhcp_info": lease.to_discovery_dict() if lease else None,
                    "dhcp_status": "no_match" if settings.DHCP_LEASE_FILE else "not_configured",
                }])
                if not results:
                    raise RuntimeError("No identification result was collected")
                enhanced = results[0]

                result = await session.execute(select(Device).where(Device.id == device_id))
                device = result.scalar_one_or_none()
                if device is None:
                    raise LookupError("Device not found")
                if device.ip_address != device_ip:
                    raise DeviceIdentityMismatchError("The device IP changed during identification")

                if enhanced.primary_hostname and (not device.hostname or device.hostname.endswith(".local")):
                    device.hostname = enhanced.primary_hostname
                if enhanced.friendly_name:
                    device.friendly_name = enhanced.friendly_name
                if enhanced.manufacturer:
                    device.manufacturer = enhanced.manufacturer
                    if not device.vendor:
                        device.vendor = enhanced.manufacturer
                if self.device_info_scanner._valid_model(enhanced.model):
                    device.model = enhanced.model
                if enhanced.open_ports:
                    device.open_ports = json.dumps(sorted(set(enhanced.open_ports)))
                services = list(dict.fromkeys([*enhanced.mdns_services, *enhanced.services]))
                if services:
                    device.services = json.dumps(list(dict.fromkeys([
                        *self._parse_json_list(device.services),
                        *services,
                    ])))
                device.discovery_info = self._merge_discovery_info(
                    device.discovery_info,
                    self._serialise_discovery_info(enhanced),
                )
                device.set_identification(self._classify_device(
                    enhanced,
                    vendor=device.vendor,
                    existing=device,
                ))
                device.last_deep_scan_at = datetime.now(timezone.utc)
                device.updated_at = datetime.now(timezone.utc)
                await session.commit()
                await session.refresh(device)

                await self._notify_callbacks("device_identified", {"device_id": device.id})
                return device
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

                lease_result = load_dhcp_leases(
                    settings.DHCP_LEASE_FILE,
                    settings.DHCP_LEASE_FORMAT,
                )
                lease_by_mac = lease_result.by_mac()
                for diagnostic in lease_result.diagnostics:
                    print(f"⚠️ DHCP lease input: {diagnostic}")
                
                # Determine which devices need the more intrusive probes.
                # mDNS/DNS metadata is still refreshed for every discovered
                # host below, otherwise known devices stop receiving new
                # hostnames and service announcements.
                devices_needing_deep_scan = []
                if deep_scan and discovered:
                    for disc_device in discovered:
                        existing_device = device_lookup.get(self._normalise_mac(disc_device.mac_address))
                        if existing_device is None or self._should_deep_scan_device(existing_device):
                            devices_needing_deep_scan.append(disc_device)
                    
                    if devices_needing_deep_scan:
                        print(f"🔍 Performing scheduled deep probes on {len(devices_needing_deep_scan)}/{len(discovered)} devices; refreshing multicast/DNS for all...")
                        skipped_count = len(discovered) - len(devices_needing_deep_scan)
                        if skipped_count > 0:
                            print(f"   ⏭️  Skipped {skipped_count} devices with complete information")
                    else:
                        print(f"✨ All {len(discovered)} devices have complete information - refreshing mDNS/DNS only")

                # Release the read transaction while network probes are in
                # flight. A fresh snapshot is loaded before applying changes.
                await session.rollback()
                
                # Perform enhanced device info gathering for selected devices
                enhanced_info_map = {}
                if deep_scan and discovered:
                    try:
                        deep_macs = {
                            self._normalise_mac(device.mac_address)
                            for device in devices_needing_deep_scan
                        }
                        devices_to_scan = [
                            {
                                'ip': d.ip_address,
                                'mac': d.mac_address,
                                'profile': 'deep' if self._normalise_mac(d.mac_address) in deep_macs else 'light',
                                'dhcp_info': (
                                    lease_by_mac[self._normalise_mac(d.mac_address)].to_discovery_dict()
                                    if self._normalise_mac(d.mac_address) in lease_by_mac else None
                                ),
                                'dhcp_status': 'no_match' if settings.DHCP_LEASE_FILE else 'not_configured',
                            }
                            for d in discovered
                        ]
                        print(f"📋 Discovery scan will check {len(devices_to_scan)} devices: {[d['ip'] for d in devices_to_scan]}")
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
                devices_to_merge: list[tuple[Device, Device]] = []
                for disc_device in discovered:
                    observed_mac = self._normalise_mac(disc_device.mac_address)
                    device = device_lookup.get(observed_mac)
                    if device is not None and self._is_private_mac(observed_mac) and not device.is_known:
                        # A previous scan may already have created this
                        # randomized address as an unknown row. Try to attach
                        # it to a known record before treating the exact MAC
                        # match as authoritative.
                        known_match = self._find_rotating_mac_match(
                            disc_device,
                            enhanced_info_map.get(disc_device.ip_address),
                            existing_device_list,
                            matched_device_ids | {device.id},
                            identity_hint=device,
                        )
                        if known_match is not None and known_match.is_known:
                            devices_to_merge.append((device, known_match))
                            matched_devices[observed_mac] = known_match
                            matched_device_ids.update({device.id, known_match.id})
                            continue
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

                for source, target in devices_to_merge:
                    await self._merge_device_records(source, target, session)
                
                # Track statistics
                devices_found = len(discovered)
                devices_online = 0
                devices_new = 0
                
                # Handle devices not found in this scan - use grace period
                current_macs = {self._normalise_mac(d.mac_address) for d in discovered}
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
                    
                    # Extract friendly name (from Avahi/UPnP)
                    friendly_name = enhanced.friendly_name if enhanced else None
                    
                    # Get open ports as JSON string
                    open_ports_str = None
                    if enhanced and enhanced.open_ports:
                        import json
                        open_ports_str = json.dumps(enhanced.open_ports)
                    
                    # Get all service names as JSON. Previously only the
                    # first ten mDNS services were persisted, and port-based
                    # services were discarded entirely before reaching the UI.
                    services_str = None
                    if enhanced:
                        discovered_services = []
                        for service in [*enhanced.mdns_services, *enhanced.services]:
                            if service and service not in discovered_services:
                                discovered_services.append(service)
                        if discovered_services:
                            services_str = json.dumps(discovered_services)

                    discovery_info_str = self._serialise_discovery_info(enhanced)
                    
                    observed_mac = self._normalise_mac(disc_device.mac_address)
                    device = matched_devices.get(observed_mac) or device_lookup.get(observed_mac)
                    identification = self._classify_device(
                        enhanced,
                        vendor=vendor,
                        existing=device,
                    ) if enhanced else None
                    if device is not None:
                        # Update existing device
                        old_ip = device.ip_address
                        was_online = device.is_online

                        # Preserve the old address as an alias before moving
                        # the current address to the newly observed private
                        # MAC. This keeps future scans attached to one row.
                        old_mac = self._normalise_mac(device.mac_address)
                        if old_mac != observed_mac:
                            aliases = [alias for alias in self._mac_aliases(device) if alias != observed_mac]
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
                        
                        # Friendly names are inferred; the structured identity
                        # profile below stays separate from user-entered type.
                        if friendly_name:
                            device.friendly_name = friendly_name
                        
                        # Update open ports
                        if open_ports_str:
                            device.open_ports = open_ports_str
                        
                        # Update services
                        if services_str:
                            merged_services = list(dict.fromkeys([
                                *self._parse_json_list(device.services),
                                *json.loads(services_str),
                            ]))
                            device.services = json.dumps(merged_services)

                        # Keep protocol responses such as SSDP headers,
                        # UPnP model data, HTTP server/title and every mDNS
                        # hostname available for the details drawer.
                        if discovery_info_str:
                            device.discovery_info = self._merge_discovery_info(
                                device.discovery_info,
                                discovery_info_str,
                            )
                        if identification and self._should_store_identification(
                            device.identification,
                            identification,
                            enhanced.scan_profile,
                        ):
                            device.set_identification(identification)
                        if enhanced and enhanced.scan_profile != "light":
                            device.last_deep_scan_at = datetime.now(timezone.utc)
                        
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
                            open_ports=open_ports_str,
                            services=services_str,
                            discovery_info=discovery_info_str,
                            is_online=True,
                            is_known=False,  # New device starts as unknown
                            missed_scans=0,
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc)
                        )
                        if identification:
                            device.set_identification(identification)
                        if enhanced and enhanced.scan_profile != "light":
                            device.last_deep_scan_at = datetime.now(timezone.utc)
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
