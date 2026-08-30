"""
Enhanced device information discovery using multiple protocols:
- mDNS/Bonjour (Apple devices, printers, smart devices)
- SSDP/UPnP (Smart TVs, media devices, routers)
- NetBIOS (Windows devices)
- SNMP (Network equipment)
- HTTP/HTTPS probing (Web interfaces)
- DHCp fingerprinting
- TCP/UDP port scanning for service detection
"""

import asyncio
import logging
import socket
import struct
import ipaddress
import ssl
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import aiohttp
import json
import threading

logger = logging.getLogger(__name__)

# Import Avahi scanner for mDNS discovery
try:
    from .avahi_scanner import avahi_scanner, AvahiScanner, AvahiDeviceInfo
    AVAHI_AVAILABLE = AvahiScanner.is_available()
except ImportError:
    AVAHI_AVAILABLE = False
    avahi_scanner = None

# mDNS/DNS-SD constants
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# SSDP constants  
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

# NetBIOS constants
NETBIOS_PORT = 137

# Shared Zeroconf instance management
_zeroconf_instance = None
_zeroconf_lock = threading.Lock()
_zeroconf_services_cache: Dict[str, List[tuple]] = {}  # IP -> [(service_type, name, info)]
_zeroconf_last_scan = None

def _get_zeroconf(interfaces: Optional[List[str]] = None):
    """Get or create a shared Zeroconf instance."""
    global _zeroconf_instance
    with _zeroconf_lock:
        if _zeroconf_instance is None:
            try:
                from zeroconf import Zeroconf
                _zeroconf_instance = Zeroconf(interfaces=interfaces) if interfaces else Zeroconf()
            except Exception:
                pass
        return _zeroconf_instance

def _close_zeroconf():
    """Close the shared Zeroconf instance."""
    global _zeroconf_instance
    with _zeroconf_lock:
        if _zeroconf_instance is not None:
            try:
                _zeroconf_instance.close()
            except Exception:
                pass
            _zeroconf_instance = None

# Common service ports for device type detection
COMMON_PORTS = {
    22: ("ssh", "Server/Network Device"),
    23: ("telnet", "Network Device"),
    53: ("dns", "DNS Server"),
    80: ("http", "Web Server"),
    443: ("https", "Web Server"),
    445: ("smb", "Windows/NAS"),
    548: ("afp", "Apple Device"),
    631: ("ipp", "Printer"),
    3389: ("rdp", "Windows"),
    5000: ("upnp", "Smart Device"),
    5001: ("synology", "Synology NAS"),
    7000: ("airtunes", "Apple TV"),
    8080: ("http-alt", "Web Server"),
    8443: ("https-alt", "Web Server"),
    9100: ("jetdirect", "Printer"),
    32400: ("plex", "Plex Server"),
    49152: ("upnp", "UPnP Device"),
    62078: ("iphone-sync", "iPhone/iPad"),
}

# The manual Identify action uses a larger, still deterministic set of ports.
# These are product/protocol signals rather than a generic top-ports scan.
IDENTIFY_PORTS = {
    **COMMON_PORTS,
    21: ("ftp", "Server/Embedded Device"),
    25: ("smtp", "Mail Server"),
    110: ("pop3", "Mail Server"),
    139: ("netbios-ssn", "Windows/NAS"),
    143: ("imap", "Mail Server"),
    515: ("lpd", "Printer"),
    554: ("rtsp", "Camera/Media Device"),
    993: ("imaps", "Mail Server"),
    995: ("pop3s", "Mail Server"),
    1400: ("sonos", "Sonos Speaker"),
    1883: ("mqtt", "IoT Device"),
    2869: ("upnp-event", "Windows/UPnP Device"),
    3689: ("daap", "Apple Media Device"),
    5357: ("ws-discovery", "Windows/Printer"),
    6668: ("tuya", "IoT Device"),
    7547: ("cwmp", "Router/CPE"),
    8000: ("camera-admin", "Camera/NVR"),
    8008: ("cast-http", "Google Cast Device"),
    8009: ("cast-control", "Google Cast Device"),
    8060: ("roku-ecp", "Roku"),
    8123: ("home-assistant", "Home Assistant"),
    8883: ("mqtt-tls", "IoT Device"),
    37777: ("dahua", "Camera/NVR"),
}

HTTP_PORT_SCHEMES = {
    80: "http", 443: "https", 5000: "http", 5001: "https",
    7000: "http", 8000: "http", 8008: "http", 8060: "http",
    8080: "http", 8123: "http", 8443: "https", 32400: "http",
    37777: "http",
}
TLS_PORTS = {443, 5001, 8443, 8883, 993, 995}
BANNER_PORTS = {21, 22, 23, 25, 110, 143}
MAX_RESPONSE_BYTES = 64 * 1024


@dataclass
class EnhancedDeviceInfo:
    """Enhanced device information from multiple discovery methods."""
    ip_address: str
    mac_address: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    friendly_name: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    os_info: Optional[str] = None
    services: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    mdns_services: List[str] = field(default_factory=list)
    ssdp_info: Dict[str, Any] = field(default_factory=dict)
    netbios_name: Optional[str] = None
    http_info: Dict[str, Any] = field(default_factory=dict)
    upnp_info: Dict[str, Any] = field(default_factory=dict)
    banners: Dict[str, str] = field(default_factory=dict)
    tls_info: Dict[str, Any] = field(default_factory=dict)
    dhcp_info: Dict[str, Any] = field(default_factory=dict)
    probe_status: Dict[str, str] = field(default_factory=dict)
    scan_profile: str = "deep"
    
    @property
    def primary_hostname(self) -> Optional[str]:
        """Get the best hostname available."""
        if self.hostnames:
            # Prefer non-.local hostnames
            for h in sorted(self.hostnames, key=lambda value: value.lower()):
                if not h.endswith('.local'):
                    return h
            return sorted(self.hostnames, key=lambda value: (len(value), value.lower()))[0]
        return self.netbios_name
    
    @property
    def detected_type(self) -> Optional[str]:
        """Detect device type from gathered information."""
        if self.device_type:
            return self.device_type
            
        # Detect from services
        services_lower = [s.lower() for s in self.services + self.mdns_services]
        
        if any('airplay' in s or 'raop' in s for s in services_lower):
            return "AirPlay-capable device"
        if any('homekit' in s for s in services_lower):
            return "HomeKit Device"
        if any('googlecast' in s or 'chromecast' in s for s in services_lower):
            return "Chromecast"
        if any('printer' in s or 'ipp' in s or '_pdl' in s for s in services_lower):
            return "Printer"
        if any('scanner' in s for s in services_lower):
            return "Scanner"
        if any('spotify' in s for s in services_lower):
            return "Spotify Connect Device"
        if any('sonos' in s for s in services_lower):
            return "Sonos Speaker"
        if any('hue' in s for s in services_lower):
            return "Philips Hue"
        if any('smb' in s or 'afp' in s or 'nfs' in s for s in services_lower):
            return "NAS / File Server"
            
        # Detect from ports
        if 9100 in self.open_ports or 631 in self.open_ports:
            return "Printer"
        if 32400 in self.open_ports:
            return "Plex Media Server"
        if 5001 in self.open_ports:
            return "Synology NAS"
        if 445 in self.open_ports or 3389 in self.open_ports:
            return "Windows PC"
        if 548 in self.open_ports:
            return "Mac"
        if 62078 in self.open_ports:
            return "iPhone/iPad"
        if 22 in self.open_ports and not any(p in self.open_ports for p in [80, 443]):
            return "Linux Server"
            
        # Detect from vendor
        if self.vendor:
            vendor_lower = self.vendor.lower()
            if 'apple' in vendor_lower:
                return "Apple Device"
            if 'samsung' in vendor_lower:
                return "Samsung Device"
            if 'google' in vendor_lower:
                return "Google Device"
            if 'amazon' in vendor_lower:
                return "Amazon Device"
            if 'sonos' in vendor_lower:
                return "Sonos Speaker"
            if 'roku' in vendor_lower:
                return "Roku"
            if 'philips' in vendor_lower and 'hue' in str(self.mdns_services).lower():
                return "Philips Hue"
            if any(x in vendor_lower for x in ['netgear', 'tp-link', 'asus', 'linksys', 'ubiquiti', 'cisco']):
                return "Network Equipment"
            if 'raspberry' in vendor_lower:
                return "Raspberry Pi"
            if 'espressif' in vendor_lower or 'tuya' in vendor_lower:
                return "IoT Device"
                
        # Detect from SSDP
        if self.ssdp_info:
            device_type = self.ssdp_info.get('device_type', '')
            if 'MediaRenderer' in device_type:
                return "Media Renderer"
            if 'MediaServer' in device_type:
                return "Media Server"
            if 'InternetGateway' in device_type:
                return "Router"
                
        return None


class DeviceInfoScanner:
    """Enhanced device information scanner using multiple protocols."""
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    @staticmethod
    def _valid_model(value: Optional[str]) -> bool:
        if not value:
            return False
        cleaned = value.strip()
        if len(cleaned) < 2 or re.fullmatch(r"\d+(?:,\d+)+", cleaned):
            return False
        return True
        
    async def get_device_info(
        self,
        ip: str,
        mac: Optional[str] = None,
        avahi_info: Optional['AvahiDeviceInfo'] = None,
        scan_profile: str = "deep",
        ssdp_responses: Optional[List[Dict[str, str]]] = None,
        dhcp_info: Optional[Dict[str, Any]] = None,
        dhcp_status: str = "not_configured",
    ) -> EnhancedDeviceInfo:
        """
        Gather comprehensive device information using all available methods.
        
        Args:
            ip: Device IP address
            mac: Optional MAC address (for vendor lookup)
            avahi_info: Optional pre-fetched Avahi device info
            
        Returns:
            EnhancedDeviceInfo with all discovered information
        """
        if scan_profile not in {"light", "deep", "identify"}:
            raise ValueError(f"Unknown scan profile: {scan_profile}")
        info = EnhancedDeviceInfo(ip_address=ip, mac_address=mac, scan_profile=scan_profile)
        if dhcp_info:
            info.dhcp_info = dhcp_info
            info.probe_status["dhcp"] = "responded"
            hostname = dhcp_info.get("hostname")
            if hostname and hostname not in info.hostnames:
                info.hostnames.append(hostname)
        else:
            info.probe_status["dhcp"] = dhcp_status
        
        # If we have Avahi info, use it first (it's usually the best source)
        if avahi_info:
            self._apply_avahi_info(avahi_info, info)
            info.probe_status["mdns"] = "responded"
        elif AVAHI_AVAILABLE:
            info.probe_status["mdns"] = "no_response"

        await self._apply_ssdp_responses(
            info,
            ssdp_responses or [],
            fetch_descriptions=scan_profile != "light",
        )
        
        # DNS and mDNS are useful for every device. The more intrusive probes
        # are only run for devices selected for a deep refresh by the caller.
        # This lets normal scans refresh names/services for the whole LAN
        # without throwing away the deep-scan optimisation for known hosts.
        tasks = [self._resolve_dns(ip, info)]
        if scan_profile != "light":
            tasks.extend([
                self._scan_ports(ip, info, ports=list(IDENTIFY_PORTS if scan_profile == "identify" else COMMON_PORTS)),
                self._probe_netbios(ip, info),
            ])
        
        # Only probe mDNS if we didn't get Avahi data
        if not avahi_info:
            tasks.append(self._probe_mdns(ip, info))
        
        # Protect the loop from long hangs by bounding total time
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout * (10 if scan_profile == "identify" else 6)
            )
        except asyncio.TimeoutError:
            info.probe_status["scan"] = "timeout"

        # HTTP, banner and TLS probes depend on the open-port result and run in
        # a second bounded phase. Routine light scans never reach this phase.
        if scan_profile != "light":
            follow_up = [self._probe_http(ip, info)]
            if scan_profile == "identify":
                follow_up.extend([self._probe_banners(ip, info), self._probe_tls(ip, info)])
            try:
                await asyncio.wait_for(
                    asyncio.gather(*follow_up, return_exceptions=True),
                    timeout=self.timeout * (8 if scan_profile == "identify" else 5),
                )
            except asyncio.TimeoutError:
                info.probe_status["follow_up"] = "timeout"
        
        # Set device type based on gathered info
        if not info.device_type:
            info.device_type = info.detected_type
            
        return info
    
    def _apply_avahi_info(self, avahi_info: 'AvahiDeviceInfo', info: EnhancedDeviceInfo):
        """Apply Avahi-discovered information to EnhancedDeviceInfo."""
        # Add hostnames
        for hostname in avahi_info.hostnames:
            if hostname and hostname not in info.hostnames:
                info.hostnames.append(hostname)
        
        # Keep friendly service names separate from DNS hostnames. The old
        # implementation mixed them together, which made the value displayed
        # as "hostname" depend on whichever mDNS service arrived first.
        friendly_name = avahi_info.friendly_name
        if friendly_name and not info.friendly_name:
            info.friendly_name = friendly_name
        
        # Add model info
        if self._valid_model(avahi_info.model) and not info.model:
            info.model = avahi_info.model
        
        # Add manufacturer
        if avahi_info.manufacturer and not info.manufacturer:
            info.manufacturer = avahi_info.manufacturer
        
        # Add device type
        if avahi_info.device_type and not info.device_type:
            info.device_type = avahi_info.device_type
        
        # Add mDNS services, preserving every service found in the live browse.
        for service in avahi_info.services:
            service_name = avahi_scanner._decode_avahi_string(service.service_name)
            service_str = f"{service_name} ({service.service_type})"
            if service_str not in info.mdns_services:
                info.mdns_services.append(service_str)
    
    async def scan_network_enhanced(self, devices: List[Dict]) -> List[EnhancedDeviceInfo]:
        """
        Scan multiple devices for enhanced information.
        
        Args:
            devices: List of dicts with 'ip' and optionally 'mac' keys
            
        Returns:
            List of EnhancedDeviceInfo objects
        """
        # Collect all device IPs
        device_ips: Set[str] = set()
        for d in devices:
            ip = d.get('ip') or d.get('ip_address')
            if ip:
                device_ips.add(ip)
        
        # IMPORTANT: Only associate mDNS results with the devices we were
        # given. A browse can see other interfaces and container services.
        print(f"📋 Discovery scan will check {len(device_ips)} devices: {sorted(list(device_ips))}")
        
        # Try Avahi scanner first (much more reliable on Linux)
        avahi_cache: Dict[str, 'AvahiDeviceInfo'] = {}
        if AVAHI_AVAILABLE and avahi_scanner:
            try:
                logger.debug("Using avahi-browse for mDNS discovery...")
                avahi_cache = await avahi_scanner.scan_all(target_ips=device_ips)
                
                # STRICT FILTER: Only keep devices that were in our original list
                filtered_avahi = {ip: info for ip, info in avahi_cache.items() if ip in device_ips}
                avahi_cache = filtered_avahi
                
                logger.info(f"Avahi discovered info for {len(avahi_cache)} devices")
            except Exception as e:
                logger.warning(f"Avahi scan failed, falling back to Zeroconf: {e}")
        
        # Fall back to an active Zeroconf browse if Avahi is unavailable or
        # cannot reach its daemon socket.
        if not avahi_cache:
            await self._scan_mdns_bulk(device_ips)

        # SSDP is a subnet-wide multicast protocol. Send one M-SEARCH and fan
        # the collected responses back out by source IP instead of repeating
        # the same multicast for every device.
        ssdp_cache = await self._scan_ssdp_bulk(device_ips)
        
        # Reduce concurrency to avoid socket exhaustion
        semaphore = asyncio.Semaphore(4)

        async def wrapped(device: Dict) -> EnhancedDeviceInfo:
            ip = device.get('ip') or device.get('ip_address')
            mac = device.get('mac') or device.get('mac_address')
            async with semaphore:
                return await self.get_device_info(
                    ip,
                    mac,
                    avahi_cache.get(ip),
                    scan_profile=device.get(
                        'profile',
                        'deep' if device.get('deep_scan', True) else 'light',
                    ),
                    ssdp_responses=ssdp_cache.get(ip, []),
                    dhcp_info=device.get('dhcp_info'),
                    dhcp_status=device.get('dhcp_status', 'not_configured'),
                )

        tasks = [wrapped(d) for d in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter results to only include valid EnhancedDeviceInfo for requested IPs
        valid_results = []
        for result in results:
            if isinstance(result, EnhancedDeviceInfo) and result.ip_address in device_ips:
                valid_results.append(result)
        
        # Clean up after scan
        _close_zeroconf()
        
        return valid_results
    
    async def _scan_mdns_bulk(self, ips: set):
        """
        Perform a single mDNS scan to discover services for all IPs at once.
        This avoids creating multiple Zeroconf instances which exhausts socket buffers.
        """
        global _zeroconf_services_cache
        _zeroconf_services_cache.clear()
        
        try:
            from zeroconf import Zeroconf, ServiceBrowser
            from zeroconf.asyncio import AsyncServiceInfo
        except ImportError:
            return
        
        service_types = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_googlecast._tcp.local.",
            "_spotify-connect._tcp.local.",
            "_homekit._tcp.local.",
            "_hap._tcp.local.",
            "_printer._tcp.local.",
            "_ipp._tcp.local.",
            "_pdl-datastream._tcp.local.",
            "_scanner._tcp.local.",
            "_smb._tcp.local.",
            "_afpovertcp._tcp.local.",
            "_nfs._tcp.local.",
            "_ssh._tcp.local.",
            "_sftp-ssh._tcp.local.",
            "_device-info._tcp.local.",
            "_sleep-proxy._udp.local.",
            "_companion-link._tcp.local.",
            "_daap._tcp.local.",
            "_dacp._tcp.local.",
            "_touch-able._tcp.local.",
            "_appletv-v2._tcp.local.",
            "_mediaremotetv._tcp.local.",
            "_plex._tcp.local.",
            "_sonos._tcp.local.",
            "_meshcop._udp.local.",
            "_trel._udp.local.",
            "_rdlink._tcp.local.",
            "_asquic._udp.local.",
        ]
        service_type_catalog = "_services._dns-sd._udp.local."
        
        # Limit direct Zeroconf to the LAN interface when possible. Binding
        # every Docker bridge causes duplicate callbacks and can make the
        # useful physical-interface responses disappear under load.
        mdns_interfaces = self._get_mdns_interfaces(ips)
        zc = _get_zeroconf(mdns_interfaces)
        if zc is None:
            return
            
        class BulkListener:
            def __init__(self):
                self.services = []
                self.discovered_service_types = set()
                
            def add_service(self, zc, type_, name):
                if type_ == service_type_catalog:
                    self.discovered_service_types.add(name)
                else:
                    self.services.append((type_, name))
                
            def remove_service(self, zc, type_, name):
                pass
                
            def update_service(self, zc, type_, name):
                pass
        
        listener = BulkListener()
        browsers = []
        seen_services = set()
        
        async def resolve_service(service_type: str, name: str) -> None:
            """Resolve one service without blocking the active event loop."""
            try:
                sinfo = AsyncServiceInfo(service_type, name)
                if not await sinfo.async_request(zc, 1000):
                    return
                for addr in sinfo.addresses:
                    try:
                        ip = socket.inet_ntoa(addr)
                    except (OSError, ValueError):
                        continue
                    if ip not in ips:
                        continue
                    services_for_ip = _zeroconf_services_cache.setdefault(ip, [])
                    service_value = (service_type, name, sinfo)
                    if not any(existing[0] == service_type and existing[1] == name for existing in services_for_ip):
                        services_for_ip.append(service_value)
            except Exception as error:
                logger.debug("mDNS service resolution failed for %s/%s: %s", service_type, name, error)

        try:
            for st in service_types:
                try:
                    browser = ServiceBrowser(zc, st, listener)
                    browsers.append(browser)
                except Exception:
                    pass

            # Ask the LAN which additional DNS-SD service types exist. This
            # catches vendor-specific advertisements such as LG, Synology,
            # Apple device-management and Thread services without having to
            # maintain a permanently incomplete hard-coded list.
            try:
                browsers.append(ServiceBrowser(zc, service_type_catalog, listener))
            except Exception:
                pass
            
            # Wait for responses
            await asyncio.sleep(2.0)

            # Browse any service types learned from the catalog. Give the
            # newly-created browsers their own response window before
            # resolving the individual service instances.
            for discovered_type in listener.discovered_service_types:
                if discovered_type in service_types or not discovered_type.endswith(("._tcp.local.", "._udp.local.")):
                    continue
                try:
                    browsers.append(ServiceBrowser(zc, discovered_type, listener))
                except Exception:
                    pass
            await asyncio.sleep(2.0)

            # Process discovered services and cache by IP. The synchronous
            # get_service_info() API cannot be called from this asyncio loop;
            # it raises and the old broad exception handler dropped every
            # service. Resolve concurrently with the supported async API.
            unique_services = []
            for service_type, name in listener.services:
                if (service_type, name) not in seen_services:
                    seen_services.add((service_type, name))
                    unique_services.append((service_type, name))
            await asyncio.gather(*[
                resolve_service(service_type, name)
                for service_type, name in unique_services
            ], return_exceptions=True)
            logger.info(
                "Zeroconf discovered %d service instances for %d target hosts",
                sum(len(services) for services in _zeroconf_services_cache.values()),
                len(_zeroconf_services_cache),
            )
                    
        except Exception as e:
            logger.error(f"Bulk mDNS scan error: {e}")
        finally:
            for browser in browsers:
                try:
                    browser.cancel()
                except Exception:
                    pass

    @staticmethod
    def _get_mdns_interfaces(ips: Set[str]) -> List[str]:
        """Return local IPv4 addresses that share a LAN with target IPs."""
        try:
            import netifaces

            target_addresses = [ipaddress.ip_address(ip) for ip in ips]
            interfaces = []
            for interface in netifaces.interfaces():
                for address in netifaces.ifaddresses(interface).get(netifaces.AF_INET, []):
                    local_ip = address.get('addr')
                    netmask = address.get('netmask')
                    if not local_ip or not netmask:
                        continue
                    local_network = ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False)
                    if any(target in local_network for target in target_addresses):
                        interfaces.append(local_ip)
            return list(dict.fromkeys(interfaces))
        except Exception:
            return []
    
    async def _resolve_dns(self, ip: str, info: EnhancedDeviceInfo):
        """Resolve hostname via DNS (reverse lookup + fqdn)."""
        found = False
        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip
            )
            if hostname and hostname not in info.hostnames:
                info.hostnames.append(hostname)
                found = True
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            logger.debug(f"DNS resolution error for {ip}: {e}")

        # FQDN fallback (sometimes gives iPhone/Android names)
        try:
            fqdn = socket.getfqdn(ip)
            if fqdn and fqdn != ip and fqdn not in info.hostnames:
                info.hostnames.append(fqdn)
                found = True
        except Exception:
            pass
        info.probe_status["dns"] = "responded" if found else "no_response"
    
    async def _scan_ports(self, ip: str, info: EnhancedDeviceInfo, ports: Optional[List[int]] = None):
        """Quick port scan for common services."""
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        async def check_port(port: int) -> Optional[int]:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
        
        # Scan ports in parallel
        results = await asyncio.gather(*[check_port(p) for p in ports], return_exceptions=True)
        
        for port in results:
            if isinstance(port, int):
                info.open_ports.append(port)
                if port in IDENTIFY_PORTS:
                    service, device_hint = IDENTIFY_PORTS[port]
                    info.services.append(service)
        info.probe_status["tcp"] = "responded" if info.open_ports else "no_response"
    
    async def _probe_mdns(self, ip: str, info: EnhancedDeviceInfo):
        """Query mDNS/Bonjour for device services using cached results."""
        try:
            # Use cached results from bulk scan if available
            if ip in _zeroconf_services_cache:
                # Zeroconf callbacks arrive from multiple worker threads, so
                # sort before using TXT data. This keeps model selection
                # stable when one host advertises several services.
                services = sorted(
                    _zeroconf_services_cache[ip],
                    key=lambda value: (value[0], value[1]),
                )
                for service_type, name, sinfo in services:
                    info.mdns_services.append(f"{name} ({service_type})")
                    
                    # Extract device info from TXT records
                    if sinfo and sinfo.properties:
                        try:
                            props = {k.decode() if isinstance(k, bytes) else k: 
                                    v.decode() if isinstance(v, bytes) else v 
                                    for k, v in sinfo.properties.items()}
                            
                            if 'model' in props and self._valid_model(props['model']):
                                info.model = props['model']
                            if 'manufacturer' in props:
                                info.manufacturer = props['manufacturer']
                            if 'md' in props and self._valid_model(props['md']):  # Model for Apple devices
                                info.model = props['md']
                            if 'am' in props and self._valid_model(props['am']):  # Apple Model
                                info.model = info.model or props['am']
                        except Exception:
                            pass
                            
                    # Get hostname
                    if sinfo and sinfo.server:
                        hostname = sinfo.server.rstrip('.')
                        if hostname and hostname not in info.hostnames:
                            info.hostnames.append(hostname)
                info.probe_status["mdns"] = "responded" if services else "no_response"
                return
            
            # Fallback: basic mDNS query for single device (if not using bulk scan)
            await self._basic_mdns_query(ip, info)
            info.probe_status["mdns"] = "responded" if info.mdns_services else "no_response"
                
        except Exception as e:
            # Silently ignore mDNS errors to avoid log spam
            info.probe_status["mdns"] = "error"
    
    async def _basic_mdns_query(self, ip: str, info: EnhancedDeviceInfo):
        """Basic mDNS query without zeroconf library."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            
            # Construct DNS query packet for reverse lookup
            # Header: ID=0, Flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
            header = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            
            # Question: QNAME + QTYPE + QCLASS
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query_name = f"{reversed_ip}.in-addr.arpa"
            
            # Encode name: 3www6google3com0
            encoded_name = b''
            for part in query_name.split('.'):
                encoded_name += bytes([len(part)]) + part.encode()
            encoded_name += b'\x00'
            
            qtype = b'\x00\x0c'  # PTR record (12)
            qclass = b'\x00\x01'  # IN class (1)
            # Note: For unicast mDNS, we might need to set the top bit of QCLASS (QU bit)
            # But standard DNS query format is fine for port 5353 unicast usually
            
            packet = header + encoded_name + qtype + qclass
            
            # mDNS queries are multicast. Sending this packet directly to the
            # target IP is not supported by many devices and silently loses
            # the hostname fallback when Zeroconf is unavailable.
            sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
            
            try:
                data, _ = sock.recvfrom(1024)
                # Parse response (very basic parsing)
                # Skip header (12 bytes)
                # Skip question (variable)
                # Parse answer
                
                # Simple heuristic: look for strings ending in .local
                # This is a hack but avoids full DNS parsing
                # Decode all readable strings
                strings = re.findall(r'[\x20-\x7E]{3,}', data.decode('latin1'))
                for s in strings:
                    if s.endswith('.local'):
                        hostname = s.rstrip('.')
                        if hostname not in info.hostnames:
                            info.hostnames.append(hostname)

                    
            except socket.timeout:
                pass
            finally:
                sock.close()
        except Exception as e:
            logger.debug(f"Basic mDNS error for {ip}: {e}")
    
    async def _scan_ssdp_bulk(self, target_ips: Set[str]) -> Dict[str, List[Dict[str, str]]]:
        """Send one SSDP multicast search and group every response by sender."""
        if not target_ips:
            return {}
        search_request = (
            'M-SEARCH * HTTP/1.1\r\n'
            f'HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 1\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        ).encode()
        transport = None
        try:
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: BulkSSDPProtocol(target_ips),
                local_addr=('0.0.0.0', 0),
                family=socket.AF_INET
            )
            transport.sendto(search_request, (SSDP_ADDR, SSDP_PORT))
            await asyncio.sleep(1.5)
            return protocol.responses
        except Exception as error:
            logger.debug("Bulk SSDP error: %s", error)
            return {}
        finally:
            if transport is not None:
                transport.close()

    async def _apply_ssdp_responses(
        self,
        info: EnhancedDeviceInfo,
        responses: List[Dict[str, str]],
        fetch_descriptions: bool,
    ) -> None:
        if not responses:
            info.probe_status["ssdp"] = "no_response"
            return
        info.probe_status["ssdp"] = "responded"
        # Retain all unique advertisements rather than whichever packet won a
        # race. The first response is also flattened for old API consumers.
        unique: list[dict[str, str]] = []
        seen = set()
        for response in responses:
            marker = tuple(sorted(response.items()))
            if marker not in seen:
                seen.add(marker)
                unique.append(response)
        info.ssdp_info = {**unique[0], "responses": unique}

        if not fetch_descriptions:
            return
        locations = list(dict.fromkeys(
            response.get("location") for response in unique if response.get("location")
        ))[:3]
        results = await asyncio.gather(*[
            self._fetch_upnp_description(url, info) for url in locations
        ], return_exceptions=True)
        if locations and not any(result is True for result in results):
            info.probe_status["upnp"] = "no_response"

    @staticmethod
    def _is_safe_device_url(url: str, target_ip: str) -> bool:
        """Restrict device-controlled URLs to the responding host itself."""
        try:
            parsed = urlparse(url)
            return parsed.scheme in {"http", "https"} and parsed.hostname == target_ip
        except (TypeError, ValueError):
            return False

    async def _fetch_upnp_description(self, url: str, info: EnhancedDeviceInfo) -> bool:
        """Fetch a bounded UPnP description from the responding host only."""
        if not self._is_safe_device_url(url, info.ip_address):
            info.probe_status["upnp"] = "unsafe_location_rejected"
            return False
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                async with session.get(url, allow_redirects=False) as response:
                    if response.status != 200:
                        return False
                    raw = await response.content.read(MAX_RESPONSE_BYTES)
                    text = raw.decode(response.charset or "utf-8", errors="replace")
                    
                    # Parse XML
                    root = ET.fromstring(text)
                    ns = {'upnp': 'urn:schemas-upnp-org:device-1-0'}
                    
                    device = root.find('.//upnp:device', ns) or root.find('.//{urn:schemas-upnp-org:device-1-0}device')
                    
                    if device is not None:
                        for elem_name in ['friendlyName', 'manufacturer', 'modelName', 'modelDescription', 'deviceType']:
                            elem = device.find(f'upnp:{elem_name}', ns) or device.find(f'{{urn:schemas-upnp-org:device-1-0}}{elem_name}')
                            if elem is not None and elem.text:
                                if elem_name == 'friendlyName':
                                    info.friendly_name = info.friendly_name or elem.text
                                elif elem_name == 'manufacturer':
                                    info.manufacturer = elem.text
                                elif elem_name == 'modelName':
                                    info.model = elem.text
                                elif elem_name == 'deviceType':
                                    info.upnp_info['device_type'] = elem.text
                                    info.ssdp_info['device_type'] = elem.text
                    info.probe_status["upnp"] = "responded"
                    return True
        except (aiohttp.ClientError, asyncio.TimeoutError, ET.ParseError, UnicodeError, ValueError):
            return False

    async def _probe_netbios(self, ip: str, info: EnhancedDeviceInfo):
        """Query NetBIOS for Windows device names."""
        try:
            # NetBIOS name query packet
            transaction_id = b'\x00\x01'
            flags = b'\x00\x00'
            questions = b'\x00\x01'
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            
            # Encode wildcard name query
            name = '*' + '\x00' * 15
            encoded_name = b'\x20' + b''.join(
                bytes([((ord(c) >> 4) & 0x0F) + 0x41, (ord(c) & 0x0F) + 0x41])
                for c in name
            ) + b'\x00'
            
            query_type = b'\x00\x21'  # NBSTAT
            query_class = b'\x00\x01'  # IN
            
            packet = (transaction_id + flags + questions + answer_rrs +
                      authority_rrs + additional_rrs + encoded_name +
                      query_type + query_class)
            
            # Send query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(packet, (ip, NETBIOS_PORT))
            
            try:
                data, _ = sock.recvfrom(1024)
                info.probe_status["netbios"] = "responded"
                if len(data) > 56:
                    # Parse response
                    num_names = data[56]
                    offset = 57
                    
                    for _ in range(num_names):
                        if offset + 18 <= len(data):
                            name_bytes = data[offset:offset+15]
                            name_type = data[offset+15]
                            
                            # Clean up name
                            name = name_bytes.decode('ascii', errors='ignore').strip()
                            
                            # Type 0x00 is workstation name, 0x20 is file server
                            if name_type in (0x00, 0x20) and name and name != '*':
                                info.netbios_name = name
                                if name not in info.hostnames:
                                    info.hostnames.append(name)
                                break
                            
                            offset += 18
            except socket.timeout:
                info.probe_status["netbios"] = "no_response"
            finally:
                sock.close()
                
        except Exception as e:
            info.probe_status["netbios"] = "error"
            logger.debug(f"NetBIOS error for {ip}: {e}")
    
    async def _probe_http(self, ip: str, info: EnhancedDeviceInfo):
        """Inspect bounded web responses on ports already shown to be open."""
        targets = [
            (port, HTTP_PORT_SCHEMES[port])
            for port in info.open_ports if port in HTTP_PORT_SCHEMES
        ]
        if not targets:
            info.probe_status["http"] = "no_open_port"
            return

        async def probe(port: int, scheme: str) -> None:
            default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            url = f"{scheme}://{ip}{'' if default_port else f':{port}'}/"
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(url, allow_redirects=False) as response:
                        raw = await response.content.read(MAX_RESPONSE_BYTES)
                        html = raw.decode(response.charset or "utf-8", errors="replace")
                        title_match = re.search(r'<title[^>]*>([^<]{1,300})</title>', html, re.IGNORECASE)
                        metadata = {
                            "scheme": scheme,
                            "status": response.status,
                        }
                        for header in ("Server", "WWW-Authenticate", "Location"):
                            if response.headers.get(header):
                                metadata[header.lower().replace("-", "_")] = response.headers[header][:500]
                        if title_match:
                            metadata["title"] = re.sub(r"\s+", " ", title_match.group(1)).strip()
                        info.http_info[str(port)] = metadata
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, LookupError):
                return

        await asyncio.gather(*[probe(port, scheme) for port, scheme in targets], return_exceptions=True)
        info.probe_status["http"] = "responded" if info.http_info else "no_response"

    async def _probe_banners(self, ip: str, info: EnhancedDeviceInfo) -> None:
        """Read small protocol greetings and issue a safe RTSP OPTIONS probe."""
        ports = sorted(set(info.open_ports) & (BANNER_PORTS | {554}))
        if not ports:
            info.probe_status["banner"] = "no_open_port"
            return

        async def probe(port: int) -> None:
            writer = None
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
                if port == 554:
                    writer.write(f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
                    await writer.drain()
                raw = await asyncio.wait_for(reader.read(1024), timeout=min(self.timeout, 1.0))
                printable = re.sub(r"[^\x20-\x7e\r\n\t]", "", raw.decode("latin-1", errors="ignore")).strip()
                if printable:
                    info.banners[str(port)] = printable[:512]
            except (asyncio.TimeoutError, ConnectionError, OSError):
                return
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        await asyncio.gather(*[probe(port) for port in ports], return_exceptions=True)
        info.probe_status["banner"] = "responded" if info.banners else "no_response"

    async def _probe_tls(self, ip: str, info: EnhancedDeviceInfo) -> None:
        """Record protocol/cipher metadata without trusting device certificates."""
        ports = sorted(set(info.open_ports) & TLS_PORTS)
        if not ports:
            info.probe_status["tls"] = "no_open_port"
            return
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        async def probe(port: int) -> None:
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=None),
                    timeout=self.timeout,
                )
                ssl_object = writer.get_extra_info("ssl_object")
                if ssl_object:
                    cipher = ssl_object.cipher()
                    info.tls_info[str(port)] = {
                        "version": ssl_object.version(),
                        "cipher": cipher[0] if cipher else None,
                    }
            except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError):
                return
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        await asyncio.gather(*[probe(port) for port in ports], return_exceptions=True)
        info.probe_status["tls"] = "responded" if info.tls_info else "no_response"


class BulkSSDPProtocol(asyncio.DatagramProtocol):
    """Collect SSDP responses for the current set of ARP discoveries."""

    def __init__(self, target_ips: Set[str]):
        self.target_ips = target_ips
        self.responses: Dict[str, List[Dict[str, str]]] = {}
        
    def datagram_received(self, data: bytes, addr: tuple):
        if addr[0] in self.target_ips:
            response = self._parse_response(data.decode(errors="replace"))
            if response:
                values = self.responses.setdefault(addr[0], [])
                if response not in values:
                    values.append(response)
    
    def _parse_response(self, data: str) -> dict:
        """Parse SSDP response headers."""
        result = {}
        for line in data.split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                result[key.lower().strip()] = value.strip()
        return result


# Global scanner instance
device_info_scanner = DeviceInfoScanner()
