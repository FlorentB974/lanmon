"""
Avahi-based mDNS/DNS-SD scanner using avahi-browse command.

This module provides hostname and service discovery using the avahi-browse
command-line tool, which is much more reliable than Python Zeroconf library
for discovering devices on the network.

The avahi-browse command with -ratpc flags provides:
- -r: Resolve services (get IP addresses)
- -a: Show all service types
- -t: Terminate after browsing
- -p: Parseable output format
- -c: Use cached services (faster)
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import shutil

logger = logging.getLogger(__name__)


@dataclass
class AvahiService:
    """Represents a discovered mDNS/DNS-SD service."""
    interface: str
    protocol: str  # IPv4 or IPv6
    service_name: str
    service_type: str
    domain: str
    hostname: str
    ip_address: str
    port: int
    txt_records: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_ipv4(self) -> bool:
        return self.protocol == "IPv4"


@dataclass
class AvahiDeviceInfo:
    """Aggregated device information from Avahi discovery."""
    ip_address: str
    hostnames: Set[str] = field(default_factory=set)
    services: List[AvahiService] = field(default_factory=list)
    service_names: Set[str] = field(default_factory=set)  # Friendly names like "Office", "Living room"
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None
    
    @property
    def primary_hostname(self) -> Optional[str]:
        """Get the best hostname available."""
        if not self.hostnames:
            return None
        
        # Prefer non-.local hostnames
        for h in self.hostnames:
            if not h.endswith('.local'):
                return h
        
        # Return shortest .local hostname
        return min(self.hostnames, key=len)
    
    @property
    def friendly_name(self) -> Optional[str]:
        """Get the most user-friendly name for the device."""
        # Prefer service names like "Office", "Living room", "Office speaker"
        if self.service_names:
            # Filter out generic/system names and technical identifiers
            bad_prefixes = ('_', 'E9E96E', '636E5CDF', '408ACAAF', 'C06BB', 'a2eda', 'googlerpc', 'LG_SMART', 'LG-SN')
            bad_suffixes = ('-0000000', )
            good_names = []
            
            for n in self.service_names:
                # Skip technical names
                if any(n.startswith(p) for p in bad_prefixes):
                    continue
                if any(n.endswith(s) for s in bad_suffixes):
                    continue
                # Skip UUIDs and hex strings
                if len(n) > 20 and n.count('-') >= 4:
                    continue
                # Skip names with MAC-like patterns (xx-xx-xx-xx)
                if re.search(r'\d+-\d+-\d+-\d+', n):
                    continue
                # Skip names with backslashes (often technical identifiers)
                if '\\' in n:
                    continue
                # Skip very short or very long names
                if len(n) < 2 or len(n) > 50:
                    continue
                good_names.append(n)
            
            if good_names:
                # Prefer names that look like friendly names (contain spaces or are short)
                friendly = [n for n in good_names if ' ' in n and len(n) < 30]
                if friendly:
                    # Prefer shorter names with spaces
                    return min(friendly, key=len)
                # Otherwise return shortest name
                return min(good_names, key=len)
        
        # Fall back to hostname without .local
        if self.hostnames:
            for h in self.hostnames:
                name = h.replace('.local', '')
                if name and not name.startswith('_'):
                    return name
        
        return None


class AvahiScanner:
    """
    Scanner using avahi-browse for mDNS/DNS-SD service discovery.
    
    This is more reliable than Python Zeroconf library and provides
    better results on Linux systems with Avahi daemon running.
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._cache: Dict[str, AvahiDeviceInfo] = {}
        self._last_scan_time: Optional[float] = None
        self._cache_ttl = 60.0  # Cache valid for 60 seconds
    
    @staticmethod
    def is_available() -> bool:
        """Check if avahi-browse is available on the system."""
        return shutil.which('avahi-browse') is not None
    
    async def scan_all(self, target_ips: Optional[Set[str]] = None, 
                       interface: Optional[str] = None) -> Dict[str, AvahiDeviceInfo]:
        """
        Scan for all mDNS/DNS-SD services on the network.
        
        Args:
            target_ips: Optional set of IPs to filter results for
            interface: Optional network interface to scan (e.g., 'eno1', 'eth0')
            
        Returns:
            Dict mapping IP addresses to AvahiDeviceInfo objects
        """
        if not self.is_available():
            return {}
        
        # Build command
        cmd = ['avahi-browse', '-ratpc']
        if interface:
            # Filter by interface happens in parsing, not in command
            pass
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            # Parse the output
            devices = self._parse_avahi_output(output, target_ips, interface)
            
            # Update cache
            self._cache = devices
            import time
            self._last_scan_time = time.time()
            
            return devices
            
        except asyncio.TimeoutError:
            logger.warning("Avahi scan timed out")
            return self._cache
        except Exception as e:
            logger.error(f"Avahi scan error: {e}")
            return self._cache
    
    def _parse_avahi_output(self, output: str, 
                           target_ips: Optional[Set[str]] = None,
                           interface: Optional[str] = None) -> Dict[str, AvahiDeviceInfo]:
        """
        Parse avahi-browse -ratpc output.
        
        Format: =;interface;protocol;name;type;domain;hostname;address;port;txt
        Example: =;eno1;IPv4;FloNas;Web Site;local;FloNas.local;192.168.1.15;5000;"vendor=Synology"
        """
        devices: Dict[str, AvahiDeviceInfo] = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Only process resolved services (start with '=')
            if not line.startswith('='):
                continue
            
            service = self._parse_service_line(line)
            if not service:
                continue
            
            # Filter by interface if specified
            if interface and service.interface != interface:
                continue
            
            # Only process IPv4 for now (more relevant for LAN monitoring)
            if not service.is_ipv4:
                continue
            
            # Skip Docker/container bridge IPs if we have target IPs
            ip = service.ip_address
            if target_ips and ip not in target_ips:
                continue
            
            # Skip link-local and localhost
            if ip.startswith('127.') or ip.startswith('169.254.'):
                continue
            
            # Get or create device info
            if ip not in devices:
                devices[ip] = AvahiDeviceInfo(ip_address=ip)
            
            device = devices[ip]
            
            # Add service
            device.services.append(service)
            
            # Add hostname (decode escaped characters)
            if service.hostname:
                hostname = self._decode_avahi_string(service.hostname.rstrip('.'))
                if hostname:
                    device.hostnames.add(hostname)
            
            # Add service name (friendly name)
            if service.service_name:
                # Decode escaped characters like \032 (space)
                name = self._decode_avahi_string(service.service_name)
                if name:
                    device.service_names.add(name)
            
            # Extract model/manufacturer from TXT records
            self._extract_device_info(service, device)
        
        return devices
    
    def _parse_service_line(self, line: str) -> Optional[AvahiService]:
        """Parse a single service line from avahi-browse output."""
        try:
            # Split by semicolon, but handle escaped characters
            parts = line.split(';')
            
            if len(parts) < 9:
                return None
            
            # Parse fields
            # =;interface;protocol;name;type;domain;hostname;address;port;txt...
            interface = parts[1]
            protocol = parts[2]
            service_name = parts[3]
            service_type = parts[4]
            domain = parts[5]
            hostname = parts[6]
            ip_address = parts[7]
            
            try:
                port = int(parts[8])
            except (ValueError, IndexError):
                port = 0
            
            # Parse TXT records (everything after port, joined)
            txt_records = {}
            if len(parts) > 9:
                txt_str = ';'.join(parts[9:])
                txt_records = self._parse_txt_records(txt_str)
            
            return AvahiService(
                interface=interface,
                protocol=protocol,
                service_name=service_name,
                service_type=service_type,
                domain=domain,
                hostname=hostname,
                ip_address=ip_address,
                port=port,
                txt_records=txt_records
            )
            
        except Exception as e:
            return None
    
    def _parse_txt_records(self, txt_str: str) -> Dict[str, str]:
        """Parse TXT record string into key-value pairs."""
        records = {}
        
        # TXT records are space-separated key=value pairs, possibly quoted
        # Example: "vendor=Synology" "model=DS413j"
        pattern = r'"([^"]+)"'
        matches = re.findall(pattern, txt_str)
        
        for match in matches:
            if '=' in match:
                key, _, value = match.partition('=')
                records[key.strip()] = value.strip()
            else:
                # Boolean flag (presence means true)
                records[match.strip()] = 'true'
        
        # Also try unquoted key=value pairs
        unquoted = re.findall(r'(?<!["\w])(\w+)=([^\s"]+)', txt_str)
        for key, value in unquoted:
            if key not in records:
                records[key] = value
        
        return records
    
    def _decode_avahi_string(self, s: str) -> str:
        """
        Decode avahi escaped strings.
        
        Avahi uses DECIMAL escapes (not octal!):
        - \\032 = space (decimal 32)
        - \\226\\128\\153 = UTF-8 RIGHT SINGLE QUOTATION MARK (U+2019)
        """
        # Collect bytes from decimal escapes and decode as UTF-8
        byte_buffer = bytearray()
        result_parts = []
        i = 0
        
        while i < len(s):
            # Check for backslash followed by 3 digits
            if s[i] == '\\' and i + 3 < len(s) and s[i+1:i+4].isdigit():
                decimal_str = s[i+1:i+4]
                try:
                    byte_val = int(decimal_str, 10)  # DECIMAL, not octal
                    if byte_val < 256:
                        byte_buffer.append(byte_val)
                        i += 4
                        continue
                except ValueError:
                    pass
            
            # If we have buffered bytes, try to decode them as UTF-8
            if byte_buffer:
                try:
                    decoded = byte_buffer.decode('utf-8', errors='replace')
                    result_parts.append(decoded)
                except:
                    result_parts.append(byte_buffer.decode('latin-1', errors='replace'))
                byte_buffer = bytearray()
            
            result_parts.append(s[i])
            i += 1
        
        # Handle any remaining bytes
        if byte_buffer:
            try:
                decoded = byte_buffer.decode('utf-8', errors='replace')
                result_parts.append(decoded)
            except:
                result_parts.append(byte_buffer.decode('latin-1', errors='replace'))
        
        result = ''.join(result_parts)
        
        # Clean up any control characters (but keep normal whitespace)
        result = ''.join(c for c in result if ord(c) >= 32 or c in '\t\n')
        
        return result.strip()
    
    def _extract_device_info(self, service: AvahiService, device: AvahiDeviceInfo):
        """Extract model, manufacturer, and device type from service info."""
        txt = service.txt_records
        service_type = service.service_type.lower()
        
        # Skip extracting model/manufacturer from certain service types that have misleading values
        skip_model_services = ['_raop._tcp', '_airplay._tcp', 'airtunes']
        is_skip_service = any(s in service_type or s in service.service_name.lower() 
                              for s in skip_model_services)
        
        # Model detection - be careful about what we accept
        if not device.model and not is_skip_service:
            for key in ['model', 'md']:
                if key in txt:
                    value = txt[key]
                    # Reject values that are clearly not model names
                    if value and not value.startswith('0,') and len(value) > 1:
                        device.model = value
                        break
        
        # Try 'am' (Apple Model) separately as it's more reliable
        if not device.model:
            if 'am' in txt:
                value = txt['am']
                if value and len(value) > 2:
                    device.model = value
        
        # Manufacturer detection - be selective
        if not device.manufacturer:
            for key in ['vendor', 'manufacturer']:
                if key in txt:
                    value = txt[key]
                    # Reject numeric values
                    if value and not value.isdigit():
                        device.manufacturer = value
                        break
        
        # For Apple companion-link, extract model from rpMd
        if 'rpMd' in txt and not device.model:
            device.model = txt['rpMd']
        
        # For Googlecast, extract friendly name from 'fn'
        if 'fn' in txt:
            fn = txt['fn']
            if fn and fn not in device.service_names:
                device.service_names.add(fn)
        
        # Device type detection from service type and TXT records
        if not device.device_type:
            service_type = service.service_type.lower()
            
            # Detect from service type
            if '_hap._tcp' in service_type or '_homekit' in service_type:
                device.device_type = 'HomeKit Device'
            elif '_airplay' in service_type or '_raop' in service_type:
                device.device_type = 'AirPlay Device'
            elif '_googlecast' in service_type:
                device.device_type = 'Chromecast'
            elif '_printer' in service_type or '_ipp' in service_type or '_pdl' in service_type:
                device.device_type = 'Printer'
            elif '_smb' in service_type:
                device.device_type = 'File Server (SMB)'
            elif '_afp' in service_type:
                device.device_type = 'File Server (AFP)'
            elif '_ssh' in service_type or '_sftp' in service_type:
                device.device_type = 'SSH Server'
            elif '_http' in service_type:
                device.device_type = 'Web Server'
            elif '_matter' in service_type:
                device.device_type = 'Matter Device'
            elif '_spotify' in service_type:
                device.device_type = 'Spotify Connect'
            elif '_sonos' in service_type:
                device.device_type = 'Sonos Speaker'
            elif '_lg-smart' in service_type:
                device.device_type = 'LG Smart Device'
            elif '_meshcop' in service_type or '_trel' in service_type:
                device.device_type = 'Thread Border Router'
            elif '_companion-link' in service_type:
                device.device_type = 'Apple Device'
            elif '_sleep-proxy' in service_type:
                device.device_type = 'Sleep Proxy (Apple)'
        
        # Refine device type from model info (this can override service-based detection)
        if device.model:
            model_lower = device.model.lower()
            if 'appletv' in model_lower:
                device.device_type = 'Apple TV'
            elif 'macbook' in model_lower:
                device.device_type = 'MacBook'
            elif 'imac' in model_lower:
                device.device_type = 'iMac'
            elif 'mac' in model_lower and 'pro' in model_lower:
                device.device_type = 'Mac Pro'
            elif 'mac' in model_lower and 'mini' in model_lower:
                device.device_type = 'Mac mini'
            elif 'homepod' in model_lower:
                device.device_type = 'HomePod'
            elif 'iphone' in model_lower:
                device.device_type = 'iPhone'
            elif 'ipad' in model_lower:
                device.device_type = 'iPad'
            elif 'xserve' in model_lower or model_lower.startswith('ds'):
                device.device_type = 'NAS'
            elif 'nvr' in model_lower or 'dhi-nvr' in model_lower:
                device.device_type = 'NVR (Security Camera Recorder)'
            elif 'nanoleaf' in model_lower:
                device.device_type = 'Nanoleaf Light'
            elif 'meross' in model_lower or model_lower.startswith('mss') or model_lower.startswith('msg'):
                device.device_type = 'Meross Smart Device'
            elif 'eufy' in model_lower:
                device.device_type = 'Eufy Device'
            elif 'scrypted' in model_lower:
                device.device_type = 'Scrypted Server'
            elif 'lg sn' in model_lower or 'lg soundbar' in model_lower:
                device.device_type = 'LG Soundbar'
        
        # Check manufacturer for hints (only if device type not set)
        if not device.device_type and device.manufacturer:
                mfr_lower = device.manufacturer.lower()
                if 'synology' in mfr_lower:
                    device.device_type = 'Synology NAS'
                elif 'apple' in mfr_lower:
                    device.device_type = 'Apple Device'
                elif 'lg' in mfr_lower:
                    device.device_type = 'LG Device'
    
    def get_device_info(self, ip: str) -> Optional[AvahiDeviceInfo]:
        """Get cached device info for an IP address."""
        return self._cache.get(ip)
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """Get the primary hostname for an IP address."""
        device = self._cache.get(ip)
        if device:
            return device.primary_hostname
        return None
    
    def get_friendly_name(self, ip: str) -> Optional[str]:
        """Get a user-friendly name for an IP address."""
        device = self._cache.get(ip)
        if device:
            return device.friendly_name
        return None


# Global scanner instance
avahi_scanner = AvahiScanner()


async def scan_with_avahi(target_ips: Optional[Set[str]] = None,
                         interface: Optional[str] = None) -> Dict[str, AvahiDeviceInfo]:
    """
    Convenience function to scan with Avahi.
    
    Args:
        target_ips: Optional set of IPs to filter results for
        interface: Optional network interface name (e.g., 'eno1')
        
    Returns:
        Dict mapping IP addresses to AvahiDeviceInfo objects
    """
    return await avahi_scanner.scan_all(target_ips, interface)
