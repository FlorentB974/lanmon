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
import re
import xml.etree.ElementTree as ET
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

def _get_zeroconf():
    """Get or create a shared Zeroconf instance."""
    global _zeroconf_instance
    with _zeroconf_lock:
        if _zeroconf_instance is None:
            try:
                from zeroconf import Zeroconf
                _zeroconf_instance = Zeroconf()
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


@dataclass
class EnhancedDeviceInfo:
    """Enhanced device information from multiple discovery methods."""
    ip_address: str
    mac_address: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
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
    
    @property
    def primary_hostname(self) -> Optional[str]:
        """Get the best hostname available."""
        if self.hostnames:
            # Prefer non-.local hostnames
            for h in self.hostnames:
                if not h.endswith('.local'):
                    return h
            return self.hostnames[0]
        return self.netbios_name
    
    @property
    def detected_type(self) -> Optional[str]:
        """Detect device type from gathered information."""
        if self.device_type:
            return self.device_type
            
        # Detect from services
        services_lower = [s.lower() for s in self.services + self.mdns_services]
        
        if any('airplay' in s or 'raop' in s for s in services_lower):
            return "Apple TV / AirPlay"
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
        
    async def get_device_info(self, ip: str, mac: Optional[str] = None, 
                              avahi_info: Optional['AvahiDeviceInfo'] = None) -> EnhancedDeviceInfo:
        """
        Gather comprehensive device information using all available methods.
        
        Args:
            ip: Device IP address
            mac: Optional MAC address (for vendor lookup)
            avahi_info: Optional pre-fetched Avahi device info
            
        Returns:
            EnhancedDeviceInfo with all discovered information
        """
        info = EnhancedDeviceInfo(ip_address=ip, mac_address=mac)
        
        # If we have Avahi info, use it first (it's usually the best source)
        if avahi_info:
            self._apply_avahi_info(avahi_info, info)
        
        # Run all discovery methods in parallel
        tasks = [
            self._resolve_dns(ip, info),
            self._scan_ports(ip, info),
            self._probe_ssdp(ip, info),
            self._probe_netbios(ip, info),
            self._probe_http(ip, info),
        ]
        
        # Only probe mDNS if we didn't get Avahi data
        if not avahi_info:
            tasks.append(self._probe_mdns(ip, info))
        
        # Protect the loop from long hangs by bounding total time
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout * 6  # generous cap per device
            )
        except asyncio.TimeoutError:
            pass
        
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
        
        # Add friendly service names as potential hostnames
        friendly_name = avahi_info.friendly_name
        if friendly_name and friendly_name not in info.hostnames:
            # Insert at the beginning as it's usually the best name
            info.hostnames.insert(0, friendly_name)
        
        # Add model info
        if avahi_info.model and not info.model:
            info.model = avahi_info.model
        
        # Add manufacturer
        if avahi_info.manufacturer and not info.manufacturer:
            info.manufacturer = avahi_info.manufacturer
        
        # Add device type
        if avahi_info.device_type and not info.device_type:
            info.device_type = avahi_info.device_type
        
        # Add mDNS services
        for service in avahi_info.services:
            service_str = f"{service.service_name} ({service.service_type})"
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
        
        # IMPORTANT: Only scan the devices we were given, don't discover new ones
        print(f"📋 Deep scan will check {len(device_ips)} devices: {sorted(list(device_ips))}")
        
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
        
        # Fall back to Zeroconf bulk scan if Avahi didn't find anything
        if not avahi_cache:
            await self._scan_mdns_bulk(device_ips)
        
        # Reduce concurrency to avoid socket exhaustion
        semaphore = asyncio.Semaphore(4)

        async def wrapped(device: Dict) -> EnhancedDeviceInfo:
            ip = device.get('ip') or device.get('ip_address')
            mac = device.get('mac') or device.get('mac_address')
            async with semaphore:
                return await self.get_device_info(ip, mac, avahi_cache.get(ip))

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
            "_ssh._tcp.local.",
            "_device-info._tcp.local.",
            "_companion-link._tcp.local.",
            "_sonos._tcp.local.",
        ]
        
        zc = _get_zeroconf()
        if zc is None:
            return
            
        class BulkListener:
            def __init__(self):
                self.services = []
                
            def add_service(self, zc, type_, name):
                self.services.append((type_, name))
                
            def remove_service(self, zc, type_, name):
                pass
                
            def update_service(self, zc, type_, name):
                pass
        
        listener = BulkListener()
        browsers = []
        
        try:
            for st in service_types:
                try:
                    browser = ServiceBrowser(zc, st, listener)
                    browsers.append(browser)
                except Exception:
                    pass
            
            # Wait for responses
            await asyncio.sleep(2.0)
            
            # Process discovered services and cache by IP
            for service_type, name in listener.services:
                try:
                    sinfo = zc.get_service_info(service_type, name, timeout=500)
                    if sinfo and sinfo.addresses:
                        for addr in sinfo.addresses:
                            try:
                                ip = socket.inet_ntoa(addr)
                                if ip in ips:
                                    if ip not in _zeroconf_services_cache:
                                        _zeroconf_services_cache[ip] = []
                                    _zeroconf_services_cache[ip].append((service_type, name, sinfo))
                            except Exception:
                                pass
                except Exception:
                    pass
                    
        except Exception as e:
            logger.error(f"Bulk mDNS scan error: {e}")
        finally:
            for browser in browsers:
                try:
                    browser.cancel()
                except Exception:
                    pass
    
    async def _resolve_dns(self, ip: str, info: EnhancedDeviceInfo):
        """Resolve hostname via DNS (reverse lookup + fqdn)."""
        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip
            )
            if hostname and hostname not in info.hostnames:
                info.hostnames.append(hostname)
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            logger.debug(f"DNS resolution error for {ip}: {e}")

        # FQDN fallback (sometimes gives iPhone/Android names)
        try:
            fqdn = socket.getfqdn(ip)
            if fqdn and fqdn != ip and fqdn not in info.hostnames:
                info.hostnames.append(fqdn)
        except Exception:
            pass
    
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
                if port in COMMON_PORTS:
                    service, device_hint = COMMON_PORTS[port]
                    info.services.append(service)
    
    async def _probe_mdns(self, ip: str, info: EnhancedDeviceInfo):
        """Query mDNS/Bonjour for device services using cached results."""
        try:
            # Use cached results from bulk scan if available
            if ip in _zeroconf_services_cache:
                for service_type, name, sinfo in _zeroconf_services_cache[ip]:
                    info.mdns_services.append(f"{name} ({service_type})")
                    
                    # Extract device info from TXT records
                    if sinfo and sinfo.properties:
                        try:
                            props = {k.decode() if isinstance(k, bytes) else k: 
                                    v.decode() if isinstance(v, bytes) else v 
                                    for k, v in sinfo.properties.items()}
                            
                            if 'model' in props:
                                info.model = props['model']
                            if 'manufacturer' in props:
                                info.manufacturer = props['manufacturer']
                            if 'md' in props:  # Model for Apple devices
                                info.model = props['md']
                            if 'am' in props:  # Apple Model
                                info.model = info.model or props['am']
                        except Exception:
                            pass
                            
                    # Get hostname
                    if sinfo and sinfo.server:
                        hostname = sinfo.server.rstrip('.')
                        if hostname and hostname not in info.hostnames:
                            info.hostnames.append(hostname)
                return
            
            # Fallback: basic mDNS query for single device (if not using bulk scan)
            await self._basic_mdns_query(ip, info)
                
        except Exception as e:
            # Silently ignore mDNS errors to avoid log spam
            pass
    
    async def _basic_mdns_query(self, ip: str, info: EnhancedDeviceInfo):
        """Basic mDNS query without zeroconf library."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            
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
            
            # Send to mDNS port on the target IP (Unicast mDNS)
            sock.sendto(packet, (ip, MDNS_PORT))
            
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
    
    async def _probe_ssdp(self, ip: str, info: EnhancedDeviceInfo):
        """Query SSDP/UPnP for device information."""
        try:
            # Send M-SEARCH request
            search_request = (
                'M-SEARCH * HTTP/1.1\r\n'
                f'HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n'
                'MAN: "ssdp:discover"\r\n'
                'MX: 1\r\n'
                'ST: ssdp:all\r\n'
                '\r\n'
            ).encode()
            
            # Create UDP socket
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SSDPProtocol(ip),
                local_addr=('0.0.0.0', 0),
                family=socket.AF_INET
            )
            
            # Send directly to device
            transport.sendto(search_request, (ip, SSDP_PORT))
            
            # Wait for response
            await asyncio.sleep(1.5)
            
            if protocol.responses:
                response = protocol.responses[0]
                info.ssdp_info = response
                
                # Try to get more info from location URL
                if 'location' in response:
                    await self._fetch_upnp_description(response['location'], info)
            
            transport.close()
            
        except Exception as e:
            logger.debug(f"SSDP error for {ip}: {e}")
    
    async def _fetch_upnp_description(self, url: str, info: EnhancedDeviceInfo):
        """Fetch and parse UPnP device description."""
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # Parse XML
                    root = ET.fromstring(text)
                    ns = {'upnp': 'urn:schemas-upnp-org:device-1-0'}
                    
                    device = root.find('.//upnp:device', ns) or root.find('.//{urn:schemas-upnp-org:device-1-0}device')
                    
                    if device is not None:
                        for elem_name in ['friendlyName', 'manufacturer', 'modelName', 'modelDescription', 'deviceType']:
                            elem = device.find(f'upnp:{elem_name}', ns) or device.find(f'{{urn:schemas-upnp-org:device-1-0}}{elem_name}')
                            if elem is not None and elem.text:
                                if elem_name == 'friendlyName':
                                    if elem.text not in info.hostnames:
                                        info.hostnames.append(elem.text)
                                elif elem_name == 'manufacturer':
                                    info.manufacturer = elem.text
                                elif elem_name == 'modelName':
                                    info.model = elem.text
                                elif elem_name == 'deviceType':
                                    info.upnp_info['device_type'] = elem.text
                                    info.ssdp_info['device_type'] = elem.text

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
                pass
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"NetBIOS error for {ip}: {e}")
    
    async def _probe_http(self, ip: str, info: EnhancedDeviceInfo):
        """Probe HTTP/HTTPS for web interfaces and device info."""
        urls_to_try = [
            f"http://{ip}/",
            f"https://{ip}/",
            f"http://{ip}:8080/",
            f"http://{ip}:8443/",
        ]
        
        for url in urls_to_try:
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=2),
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status == 200:
                            # Get headers
                            server = response.headers.get('Server', '')
                            if server:
                                info.http_info['server'] = server
                                
                                # Detect device type from server header
                                server_lower = server.lower()
                                if 'synology' in server_lower:
                                    info.device_type = 'Synology NAS'
                                elif 'nginx' in server_lower or 'apache' in server_lower:
                                    info.device_type = info.device_type or 'Web Server'
                                elif 'lighttpd' in server_lower:
                                    info.device_type = info.device_type or 'Embedded Device'
                            
                            # Try to get title from HTML
                            html = await response.text()
                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
                            if title_match:
                                title = title_match.group(1).strip()
                                info.http_info['title'] = title
                                
                                # Detect from title
                                title_lower = title.lower()
                                if 'synology' in title_lower:
                                    info.device_type = 'Synology NAS'
                                elif 'router' in title_lower or 'gateway' in title_lower:
                                    info.device_type = 'Router'
                                elif 'printer' in title_lower:
                                    info.device_type = 'Printer'
                                elif 'unifi' in title_lower:
                                    info.device_type = 'Ubiquiti UniFi'
                                elif 'plex' in title_lower:
                                    info.device_type = 'Plex Media Server'
                                elif 'home assistant' in title_lower:
                                    info.device_type = 'Home Assistant'
                                elif 'pi-hole' in title_lower:
                                    info.device_type = 'Pi-hole'
                                               
                            break  # Success, don't try other ports
                            
            except Exception:
                pass


class SSDPProtocol(asyncio.DatagramProtocol):
    """SSDP/UPnP discovery protocol."""
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.responses = []
        
    def datagram_received(self, data: bytes, addr: tuple):
        if addr[0] == self.target_ip:
            response = self._parse_response(data.decode())
            self.responses.append(response)
    
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
