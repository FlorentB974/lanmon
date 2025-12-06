import asyncio
import subprocess
import re
import socket
from typing import Optional
from dataclasses import dataclass
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import our local OUI database lookup
from .oui_lookup import lookup_vendor as oui_lookup_vendor


# Fallback OUI prefixes for common manufacturers (first 6 chars of MAC)
# This is a small subset - the mac_vendor_lookup library has the full database
FALLBACK_OUI = {
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0a:27": "Apple",
    "00:0a:95": "Apple",
    "00:0d:93": "Apple",
    "00:10:fa": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:cb": "Apple",
    "00:17:f2": "Apple",
    "00:19:e3": "Apple",
    "00:1b:63": "Apple",
    "00:1c:b3": "Apple",
    "00:1d:4f": "Apple",
    "00:1e:52": "Apple",
    "00:1e:c2": "Apple",
    "00:1f:5b": "Apple",
    "00:1f:f3": "Apple",
    "00:21:e9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6c": "Apple",
    "00:23:df": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4b": "Apple",
    "00:25:bc": "Apple",
    "00:26:08": "Apple",
    "00:26:4a": "Apple",
    "00:26:b0": "Apple",
    "00:26:bb": "Apple",
    "00:30:65": "Apple",
    "00:50:e4": "Apple",
    "00:61:71": "Apple",
    "00:88:65": "Apple",
    "00:a0:40": "Apple",
    "00:c6:10": "Apple",
    "00:f4:b9": "Apple",
    "04:0c:ce": "Apple",
    "04:15:52": "Apple",
    "04:1e:64": "Apple",
    "04:26:65": "Apple",
    "04:48:9a": "Apple",
    "04:4b:ed": "Apple",
    "04:52:f3": "Apple",
    "04:54:53": "Apple",
    "04:d3:cf": "Apple",
    "04:db:56": "Apple",
    "04:e5:36": "Apple",
    "04:f1:3e": "Apple",
    "04:f7:e4": "Apple",
    "08:00:07": "Apple",
    "08:66:98": "Apple",
    "08:6d:41": "Apple",
    "10:40:f3": "Apple",
    "10:41:7f": "Apple",
    "10:9a:dd": "Apple",
    "14:10:9f": "Apple",
    "18:20:32": "Apple",
    "18:34:51": "Apple",
    "18:af:61": "Apple",
    "18:e7:f4": "Apple",
    "1c:1a:c0": "Apple",
    "1c:36:bb": "Apple",
    "1c:91:48": "Apple",
    "20:3c:ae": "Apple",
    "24:a0:74": "Apple",
    "24:ab:81": "Apple",
    "28:0b:5c": "Apple",
    "28:37:37": "Apple",
    "28:6a:b8": "Apple",
    "28:cf:e9": "Apple",
    "2c:f0:ee": "Apple",
    "30:10:e4": "Apple",
    "30:35:ad": "Apple",
    "34:08:bc": "Apple",
    "34:12:98": "Apple",
    "34:36:3b": "Apple",
    "34:c0:59": "Apple",
    "38:0f:4a": "Apple",
    "38:53:9c": "Apple",
    "38:c9:86": "Apple",
    "3c:06:30": "Apple",
    "3c:15:c2": "Apple",
    "3c:d0:f8": "Apple",
    "40:30:04": "Apple",
    "40:33:1a": "Apple",
    "40:6c:8f": "Apple",
    "40:a6:d9": "Apple",
    "40:b3:95": "Apple",
    "40:d3:2d": "Apple",
    "44:2a:60": "Apple",
    "44:d8:84": "Apple",
    "48:43:7c": "Apple",
    "48:74:6e": "Apple",
    "48:d7:05": "Apple",
    "4c:32:75": "Apple",
    "4c:57:ca": "Apple",
    "4c:8d:79": "Apple",
    "4c:b1:99": "Apple",
    "50:32:37": "Apple",
    "54:26:96": "Apple",
    "54:72:4f": "Apple",
    "54:ae:27": "Apple",
    "54:e4:3a": "Apple",
    "54:ea:a8": "Apple",
    "58:1f:aa": "Apple",
    "58:55:ca": "Apple",
    "58:b0:35": "Apple",
    "5c:59:48": "Apple",
    "5c:8d:4e": "Apple",
    "5c:96:9d": "Apple",
    "5c:97:f3": "Apple",
    "5c:f7:e6": "Apple",
    "60:03:08": "Apple",
    "60:33:4b": "Apple",
    "60:69:44": "Apple",
    "60:92:17": "Apple",
    "60:c5:47": "Apple",
    "60:d9:c7": "Apple",
    "60:f8:1d": "Apple",
    "60:fa:cd": "Apple",
    "64:20:0c": "Apple",
    "64:76:ba": "Apple",
    "64:9a:be": "Apple",
    "64:a3:cb": "Apple",
    "64:b0:a6": "Apple",
    "64:b9:e8": "Apple",
    "64:e6:82": "Apple",
    "68:09:27": "Apple",
    "68:5b:35": "Apple",
    "68:64:4b": "Apple",
    "68:96:7b": "Apple",
    "68:9c:70": "Apple",
    "68:a8:6d": "Apple",
    "68:ab:1e": "Apple",
    "68:d9:3c": "Apple",
    "68:db:ca": "Apple",
    "68:fe:f7": "Apple",
    "6c:19:c0": "Apple",
    "6c:3e:6d": "Apple",
    "6c:40:08": "Apple",
    "6c:4d:73": "Apple",
    "6c:70:9f": "Apple",
    "6c:72:e7": "Apple",
    "6c:94:f8": "Apple",
    "6c:96:cf": "Apple",
    "6c:c2:6b": "Apple",
    "70:11:24": "Apple",
    "70:3e:ac": "Apple",
    "70:48:0f": "Apple",
    "70:56:81": "Apple",
    "70:73:cb": "Apple",
    "70:81:eb": "Apple",
    "70:a2:b3": "Apple",
    "70:cd:60": "Apple",
    "70:de:e2": "Apple",
    "70:ec:e4": "Apple",
    "74:1b:b2": "Apple",
    "74:8d:08": "Apple",
    "74:e1:b6": "Apple",
    "74:e2:f5": "Apple",
    "78:31:c1": "Apple",
    "78:3a:84": "Apple",
    "78:4f:43": "Apple",
    "78:67:d7": "Apple",
    "78:6c:1c": "Apple",
    "78:7b:8a": "Apple",
    "78:88:6d": "Apple",
    "78:9f:70": "Apple",
    "78:a3:e4": "Apple",
    "78:ca:39": "Apple",
    "78:d7:5f": "Apple",
    "78:fd:94": "Apple",
    "7c:01:0a": "Apple",
    "7c:04:d0": "Apple",
    "7c:11:be": "Apple",
    "7c:50:49": "Apple",
    "7c:5c:f8": "Apple",
    "7c:6d:62": "Apple",
    "7c:6d:f8": "Apple",
    "7c:c3:a1": "Apple",
    "7c:c5:37": "Apple",
    "7c:d1:c3": "Apple",
    "7c:f0:5f": "Apple",
    "7c:fa:df": "Apple",
    "80:00:6e": "Apple",
    "80:49:71": "Apple",
    "80:82:23": "Apple",
    "80:92:9f": "Apple",
    "80:be:05": "Apple",
    "80:e6:50": "Apple",
    "80:ed:2c": "Apple",
    "84:29:99": "Apple",
    "84:38:35": "Apple",
    "84:78:8b": "Apple",
    "84:85:06": "Apple",
    "84:89:ad": "Apple",
    "84:8e:0c": "Apple",
    "84:b1:53": "Apple",
    "84:fc:fe": "Apple",
    "88:1f:a1": "Apple",
    "88:53:95": "Apple",
    "88:63:df": "Apple",
    "88:66:a5": "Apple",
    "88:c6:63": "Apple",
    "88:e8:7f": "Apple",
    "8c:00:6d": "Apple",
    "8c:29:37": "Apple",
    "8c:2d:aa": "Apple",
    "8c:58:77": "Apple",
    "8c:7b:9d": "Apple",
    "8c:7c:92": "Apple",
    "8c:85:90": "Apple",
    "8c:8e:f2": "Apple",
    "8c:fa:ba": "Apple",
    "90:27:e4": "Apple",
    "90:3c:92": "Apple",
    "90:60:f1": "Apple",
    "90:72:40": "Apple",
    "90:84:0d": "Apple",
    "90:8d:6c": "Apple",
    "90:b0:ed": "Apple",
    "90:b2:1f": "Apple",
    "90:b9:31": "Apple",
    "90:c1:c6": "Apple",
    "90:fd:61": "Apple",
    "94:94:26": "Apple",
    "94:e9:6a": "Apple",
    "94:f6:a3": "Apple",
    "98:01:a7": "Apple",
    "98:03:d8": "Apple",
    "98:10:e8": "Apple",
    "98:5a:eb": "Apple",
    "98:b8:e3": "Apple",
    "98:d6:bb": "Apple",
    "98:e0:d9": "Apple",
    "98:f0:ab": "Apple",
    "98:fe:94": "Apple",
    "9c:04:eb": "Apple",
    "9c:20:7b": "Apple",
    "9c:35:eb": "Apple",
    "9c:4f:da": "Apple",
    "9c:84:bf": "Apple",
    "9c:8b:a0": "Apple",
    "9c:e6:5e": "Apple",
    "9c:f3:87": "Apple",
    "9c:fc:01": "Apple",
    "a0:18:28": "Apple",
    "a0:3b:e3": "Apple",
    "a0:4e:a7": "Apple",
    "a0:99:9b": "Apple",
    "a0:d7:95": "Apple",
    "a0:ed:cd": "Apple",
    "a4:31:35": "Apple",
    "a4:5e:60": "Apple",
    "a4:67:06": "Apple",
    "a4:83:e7": "Apple",
    "a4:b1:97": "Apple",
    "a4:b8:05": "Apple",
    "a4:c3:61": "Apple",
    "a4:d1:8c": "Apple",
    "a4:d1:d2": "Apple",
    "a4:f1:e8": "Apple",
    "a8:20:66": "Apple",
    "a8:5b:78": "Apple",
    "a8:5c:2c": "Apple",
    "a8:66:7f": "Apple",
    "a8:86:dd": "Apple",
    "a8:88:08": "Apple",
    "a8:8e:24": "Apple",
    "a8:96:8a": "Apple",
    "a8:bb:cf": "Apple",
    "a8:be:27": "Apple",
    "a8:fa:d8": "Apple",
    "ac:29:3a": "Apple",
    "ac:3c:0b": "Apple",
    "ac:61:ea": "Apple",
    "ac:7f:3e": "Apple",
    "ac:87:a3": "Apple",
    "ac:bc:32": "Apple",
    "ac:cf:5c": "Apple",
    "ac:fd:ec": "Apple",
    "b0:19:c6": "Apple",
    "b0:34:95": "Apple",
    "b0:48:1a": "Apple",
    "b0:65:bd": "Apple",
    "b0:70:2d": "Apple",
    "b0:9f:ba": "Apple",
    "b4:18:d1": "Apple",
    "b4:8b:19": "Apple",
    "b4:9c:df": "Apple",
    "b4:f0:ab": "Apple",
    "b4:f6:1c": "Apple",
    "b8:09:8a": "Apple",
    "b8:17:c2": "Apple",
    "b8:41:a4": "Apple",
    "b8:44:d9": "Apple",
    "b8:53:ac": "Apple",
    "b8:63:4d": "Apple",
    "b8:78:2e": "Apple",
    "b8:8d:12": "Apple",
    "b8:c1:11": "Apple",
    "b8:c7:5d": "Apple",
    "b8:e8:56": "Apple",
    "b8:f6:b1": "Apple",
    "b8:ff:61": "Apple",
    "bc:3b:af": "Apple",
    "bc:4c:c4": "Apple",
    "bc:52:b7": "Apple",
    "bc:54:36": "Apple",
    "bc:67:78": "Apple",
    "bc:6c:21": "Apple",
    "bc:92:6b": "Apple",
    "bc:9f:ef": "Apple",
    "bc:a9:20": "Apple",
    "bc:d0:74": "Apple",
    "bc:ec:5d": "Apple",
    "bc:fe:d9": "Apple",
    "c0:1a:da": "Apple",
    "c0:25:67": "Apple",
    "c0:63:94": "Apple",
    "c0:84:7a": "Apple",
    "c0:9f:42": "Apple",
    "c0:a5:3e": "Apple",
    "c0:cc:f8": "Apple",
    "c0:ce:cd": "Apple",
    "c0:d0:12": "Apple",
    "c0:f2:fb": "Apple",
    "c4:2c:03": "Apple",
    "c8:1e:e7": "Apple",
    "c8:2a:14": "Apple",
    "c8:33:4b": "Apple",
    "c8:3c:85": "Apple",
    "c8:6f:1d": "Apple",
    "c8:85:50": "Apple",
    "c8:b5:b7": "Apple",
    "c8:bc:c8": "Apple",
    "c8:d0:83": "Apple",
    "c8:e0:eb": "Apple",
    "c8:f6:50": "Apple",
    "cc:08:8d": "Apple",
    "cc:20:e8": "Apple",
    "cc:25:ef": "Apple",
    "cc:29:f5": "Apple",
    "cc:44:63": "Apple",
    "cc:78:5f": "Apple",
    "cc:c7:60": "Apple",
    "d0:03:4b": "Apple",
    "d0:23:db": "Apple",
    "d0:25:98": "Apple",
    "d0:33:11": "Apple",
    "d0:4f:7e": "Apple",
    "d0:a6:37": "Apple",
    "d0:c5:f3": "Apple",
    "d0:e1:40": "Apple",
    "d4:61:9d": "Apple",
    "d4:9a:20": "Apple",
    "d4:dc:cd": "Apple",
    "d4:f4:6f": "Apple",
    "d8:00:4d": "Apple",
    "d8:1d:72": "Apple",
    "d8:30:62": "Apple",
    "d8:8f:76": "Apple",
    "d8:96:95": "Apple",
    "d8:9e:3f": "Apple",
    "d8:a2:5e": "Apple",
    "d8:bb:2c": "Apple",
    "d8:cf:9c": "Apple",
    "d8:d1:cb": "Apple",
    "dc:0c:5c": "Apple",
    "dc:2b:2a": "Apple",
    "dc:2b:61": "Apple",
    "dc:37:14": "Apple",
    "dc:41:5f": "Apple",
    "dc:56:e7": "Apple",
    "dc:86:d8": "Apple",
    "dc:9b:9c": "Apple",
    "dc:a4:ca": "Apple",
    "dc:d3:a2": "Apple",
    "e0:5f:45": "Apple",
    "e0:66:78": "Apple",
    "e0:ac:cb": "Apple",
    "e0:b5:2d": "Apple",
    "e0:b9:ba": "Apple",
    "e0:c7:67": "Apple",
    "e0:c9:7a": "Apple",
    "e0:f5:c6": "Apple",
    "e0:f8:47": "Apple",
    "e4:25:e7": "Apple",
    "e4:2b:34": "Apple",
    "e4:8b:7f": "Apple",
    "e4:98:d6": "Apple",
    "e4:9a:dc": "Apple",
    "e4:c6:3d": "Apple",
    "e4:ce:8f": "Apple",
    "e4:e0:a6": "Apple",
    "e8:04:0b": "Apple",
    "e8:06:88": "Apple",
    "e8:80:2e": "Apple",
    "e8:8d:28": "Apple",
    "ec:35:86": "Apple",
    "ec:85:2f": "Apple",
    "f0:18:98": "Apple",
    "f0:24:75": "Apple",
    "f0:79:60": "Apple",
    "f0:98:9d": "Apple",
    "f0:99:bf": "Apple",
    "f0:b0:e7": "Apple",
    "f0:c1:f1": "Apple",
    "f0:cb:a1": "Apple",
    "f0:d1:a9": "Apple",
    "f0:db:e2": "Apple",
    "f0:dc:e2": "Apple",
    "f0:f6:1c": "Apple",
    "f4:0f:24": "Apple",
    "f4:1b:a1": "Apple",
    "f4:31:c3": "Apple",
    "f4:37:b7": "Apple",
    "f4:5c:89": "Apple",
    "f4:f1:5a": "Apple",
    "f4:f9:51": "Apple",
    "f8:1e:df": "Apple",
    "f8:27:93": "Apple",
    "f8:38:80": "Apple",
    "f8:62:14": "Apple",
    "f8:95:ea": "Apple",
    "fc:25:3f": "Apple",
    "fc:e9:98": "Apple",
    "fc:fc:48": "Apple",
    # Samsung
    "00:12:47": "Samsung",
    "00:12:fb": "Samsung",
    "00:13:77": "Samsung",
    "00:15:b9": "Samsung",
    "00:16:32": "Samsung",
    "00:17:c9": "Samsung",
    "00:17:d5": "Samsung",
    "00:18:af": "Samsung",
    "00:1a:8a": "Samsung",
    "00:1d:25": "Samsung",
    "00:1d:f6": "Samsung",
    "00:1e:7d": "Samsung",
    "00:21:19": "Samsung",
    "00:21:4c": "Samsung",
    "00:21:d1": "Samsung",
    "00:21:d2": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:91": "Samsung",
    "00:24:e9": "Samsung",
    "00:25:66": "Samsung",
    "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    "00:26:5d": "Samsung",
    # Google
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "54:60:09": "Google",
    "94:eb:2c": "Google",
    "f4:f5:d8": "Google",
    "f4:f5:e8": "Google",
    # Amazon
    "00:fc:8b": "Amazon",
    "0c:47:c9": "Amazon",
    "10:2c:6b": "Amazon",
    "18:74:2e": "Amazon",
    "34:d2:70": "Amazon",
    "40:b4:cd": "Amazon",
    "44:65:0d": "Amazon",
    "50:dc:e7": "Amazon",
    "68:37:e9": "Amazon",
    "68:54:fd": "Amazon",
    "74:c2:46": "Amazon",
    "84:d6:d0": "Amazon",
    "a0:02:dc": "Amazon",
    "ac:63:be": "Amazon",
    "b4:7c:9c": "Amazon",
    "cc:9e:a2": "Amazon",
    "f0:27:2d": "Amazon",
    "fc:65:de": "Amazon",
    # Sonos
    "00:0e:58": "Sonos",
    "34:7e:5c": "Sonos",
    "48:a6:b8": "Sonos",
    "5c:aa:fd": "Sonos",
    "78:28:ca": "Sonos",
    "94:9f:3e": "Sonos",
    "b8:e9:37": "Sonos",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    # Espressif (ESP32/ESP8266 IoT)
    "08:3a:f2": "Espressif",
    "24:0a:c4": "Espressif",
    "24:62:ab": "Espressif",
    "24:6f:28": "Espressif",
    "2c:f4:32": "Espressif",
    "30:ae:a4": "Espressif",
    "3c:71:bf": "Espressif",
    "40:f5:20": "Espressif",
    "48:3f:da": "Espressif",
    "4c:11:ae": "Espressif",
    "5c:cf:7f": "Espressif",
    "60:01:94": "Espressif",
    "68:c6:3a": "Espressif",
    "80:7d:3a": "Espressif",
    "84:0d:8e": "Espressif",
    "84:cc:a8": "Espressif",
    "84:f3:eb": "Espressif",
    "8c:aa:b5": "Espressif",
    "90:97:d5": "Espressif",
    "94:b9:7e": "Espressif",
    "98:cd:ac": "Espressif",
    "a0:20:a6": "Espressif",
    "a4:7b:9d": "Espressif",
    "a4:cf:12": "Espressif",
    "ac:67:b2": "Espressif",
    "b4:e6:2d": "Espressif",
    "bc:dd:c2": "Espressif",
    "c4:4f:33": "Espressif",
    "c8:2b:96": "Espressif",
    "cc:50:e3": "Espressif",
    "d8:a0:1d": "Espressif",
    "d8:bf:c0": "Espressif",
    "dc:4f:22": "Espressif",
    "ec:fa:bc": "Espressif",
    "f4:cf:a2": "Espressif",
    # Philips Hue
    "00:17:88": "Philips Hue",
    "ec:b5:fa": "Philips Hue",
    # Ubiquiti
    "00:15:6d": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "04:18:d6": "Ubiquiti",
    "18:e8:29": "Ubiquiti",
    "24:5a:4c": "Ubiquiti",
    "44:d9:e7": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "74:83:c2": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "80:2a:a8": "Ubiquiti",
    "b4:fb:e4": "Ubiquiti",
    "dc:9f:db": "Ubiquiti",
    "e0:63:da": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    # TP-Link
    "00:31:92": "TP-Link",
    "14:cc:20": "TP-Link",
    "14:eb:b6": "TP-Link",
    "18:a6:f7": "TP-Link",
    "1c:3b:f3": "TP-Link",
    "30:b5:c2": "TP-Link",
    "50:3e:aa": "TP-Link",
    "54:c8:0f": "TP-Link",
    "60:32:b1": "TP-Link",
    "64:70:02": "TP-Link",
    "6c:5a:b0": "TP-Link",
    "78:44:fd": "TP-Link",
    "90:f6:52": "TP-Link",
    "98:da:c4": "TP-Link",
    "a0:f3:c1": "TP-Link",
    "b0:4e:26": "TP-Link",
    "c0:25:e9": "TP-Link",
    "c4:6e:1f": "TP-Link",
    "d4:6e:0e": "TP-Link",
    "d8:07:b6": "TP-Link",
    "e8:94:f6": "TP-Link",
    "ec:08:6b": "TP-Link",
    "f4:ec:38": "TP-Link",
    "f8:1a:67": "TP-Link",
    # Synology
    "00:11:32": "Synology",
}


@dataclass
class DiscoveredDevice:
    """Represents a discovered network device."""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    response_time: Optional[float] = None
    scan_method: str = "arp"


class ARPScanner:
    """ARP-based network scanner for device discovery."""
    
    def __init__(self, timeout: int = 5, retries: int = 2):
        self.timeout = timeout
        self.retries = retries  # Number of ARP scan attempts
        if SCAPY_AVAILABLE:
            conf.verb = 0  # Disable scapy verbose output
    
    async def scan_subnet(self, subnet: str) -> list[DiscoveredDevice]:
        """
        Scan a subnet for devices using multiple methods for comprehensive discovery.
        
        Args:
            subnet: Network subnet in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            List of discovered devices
        """
        all_devices = {}  # MAC -> Device mapping to deduplicate
        
        # Method 1: ARP scan with scapy (multiple attempts)
        if SCAPY_AVAILABLE:
            for attempt in range(self.retries):
                try:
                    scapy_devices = await self._scan_with_scapy(subnet)
                    for device in scapy_devices:
                        if device.mac_address not in all_devices:
                            all_devices[device.mac_address] = device
                except Exception as e:
                    print(f"Scapy scan attempt {attempt + 1} error: {e}")
                
                # Small delay between attempts
                if attempt < self.retries - 1:
                    await asyncio.sleep(0.5)
        
        # Method 2: arp-scan command line tool
        try:
            arp_scan_devices = await self._scan_with_arp_scan(subnet)
            for device in arp_scan_devices:
                if device.mac_address not in all_devices:
                    all_devices[device.mac_address] = device
        except Exception as e:
            print(f"arp-scan error: {e}")
        
        # Method 3: System ARP table (includes recently active devices)
        try:
            arp_table_devices = await self._get_arp_table()
            for device in arp_table_devices:
                if device.mac_address not in all_devices:
                    all_devices[device.mac_address] = device
        except Exception as e:
            print(f"ARP table error: {e}")
        
        # Method 4: Ping sweep to populate ARP table, then re-read
        try:
            await self._ping_sweep(subnet)
            arp_table_after_ping = await self._get_arp_table()
            for device in arp_table_after_ping:
                if device.mac_address not in all_devices:
                    all_devices[device.mac_address] = device
        except Exception as e:
            print(f"Ping sweep error: {e}")
        
        return list(all_devices.values())
    
    async def _ping_sweep(self, subnet: str) -> None:
        """Perform a quick ping sweep to populate ARP cache."""
        import ipaddress
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
            
            # Limit to first 254 hosts for performance
            hosts = hosts[:254]
            
            # Ping in batches to avoid overwhelming the network
            batch_size = 50
            for i in range(0, len(hosts), batch_size):
                batch = hosts[i:i + batch_size]
                tasks = []
                for host in batch:
                    tasks.append(self._ping_host(str(host)))
                
                # Wait for batch with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=3.0
                    )
                except asyncio.TimeoutError:
                    pass
                    
        except Exception as e:
            print(f"Ping sweep error: {e}")
    
    async def _ping_host(self, ip: str) -> bool:
        """Ping a single host."""
        try:
            process = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "1", ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
            return process.returncode == 0
        except Exception:
            return False
    
    async def verify_device_online(self, ip: str, mac: str = None) -> bool:
        """
        Verify if a specific device is online using multiple methods.
        Used to double-check before marking a device offline.
        """
        # Method 1: Ping
        if await self._ping_host(ip):
            return True
        
        # Method 2: ARP probe for specific IP
        if SCAPY_AVAILABLE:
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, self._arp_probe, ip
                )
                if result:
                    # If mac is provided, verify it matches
                    if mac and result.lower() != mac.lower():
                        return False  # Different device on this IP
                    return True
            except Exception:
                pass
        
        # Method 3: Check ARP table
        try:
            arp_devices = await self._get_arp_table()
            for device in arp_devices:
                if device.ip_address == ip:
                    if mac and device.mac_address.lower() != mac.lower():
                        return False  # Different device
                    return True
        except Exception:
            pass
        
        return False
    
    def _arp_probe(self, ip: str) -> Optional[str]:
        """Send ARP probe to specific IP and return MAC if found."""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, timeout=2, verbose=False, retry=2)[0]
            
            if result:
                return result[0][1].hwsrc.lower()
        except Exception:
            pass
        
        return None
    
    async def _scan_with_scapy(self, subnet: str) -> list[DiscoveredDevice]:
        """Scan using scapy library."""
        devices = []
        
        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self._scapy_arp_scan, subnet
            )
            devices = result
        except Exception as e:
            print(f"Scapy scan error: {e}")
        
        return devices
    
    def _scapy_arp_scan(self, subnet: str) -> list[DiscoveredDevice]:
        """Perform ARP scan using scapy (blocking)."""
        devices = []
        
        try:
            # Create ARP request packet
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            # Send and receive with increased timeout and retry
            start_time = datetime.now()
            result = srp(packet, timeout=self.timeout, verbose=False, retry=2)[0]
            
            for sent, received in result:
                response_time = (datetime.now() - start_time).total_seconds() * 1000
                
                mac = received.hwsrc.lower()
                ip = received.psrc
                
                # Get hostname
                hostname = self._resolve_hostname(ip)
                
                # Get vendor
                vendor = self._lookup_vendor(mac)
                
                devices.append(DiscoveredDevice(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    vendor=vendor,
                    response_time=response_time,
                    scan_method="arp-scapy"
                ))
        except Exception as e:
            print(f"Scapy ARP scan error: {e}")
        
        return devices
    
    async def _scan_with_arp_scan(self, subnet: str) -> list[DiscoveredDevice]:
        """Scan using arp-scan command line tool."""
        devices = []
        
        try:
            # Run arp-scan command
            process = await asyncio.create_subprocess_exec(
                "arp-scan", "--localnet", "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                devices = self._parse_arp_scan_output(output)
            else:
                # Fallback to system ARP table
                devices = await self._get_arp_table()
                
        except FileNotFoundError:
            # arp-scan not installed, use ARP table
            devices = await self._get_arp_table()
        except Exception as e:
            print(f"ARP scan error: {e}")
            devices = await self._get_arp_table()
        
        return devices
    
    def _parse_arp_scan_output(self, output: str) -> list[DiscoveredDevice]:
        """Parse output from arp-scan command."""
        devices = []
        
        # Pattern: IP\tMAC\tVendor
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)"
        
        for line in output.split("\n"):
            match = re.match(pattern, line.strip())
            if match:
                ip, mac, vendor = match.groups()
                hostname = self._resolve_hostname(ip)
                
                devices.append(DiscoveredDevice(
                    mac_address=mac.lower(),
                    ip_address=ip,
                    hostname=hostname,
                    vendor=vendor.strip() if vendor else self._lookup_vendor(mac),
                    scan_method="arp-scan"
                ))
        
        return devices
    
    async def _get_arp_table(self) -> list[DiscoveredDevice]:
        """Get devices from system ARP table."""
        devices = []
        
        try:
            process = await asyncio.create_subprocess_exec(
                "arp", "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            output = stdout.decode()
            
            # Parse ARP table output
            # Format varies by OS, common pattern: hostname (IP) at MAC
            pattern = r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})"
            
            for line in output.split("\n"):
                match = re.search(pattern, line)
                if match:
                    ip, mac = match.groups()
                    if mac != "(incomplete)" and mac != "ff:ff:ff:ff:ff:ff":
                        hostname = self._resolve_hostname(ip)
                        vendor = self._lookup_vendor(mac)
                        
                        devices.append(DiscoveredDevice(
                            mac_address=mac.lower(),
                            ip_address=ip,
                            hostname=hostname,
                            vendor=vendor,
                            scan_method="arp-table"
                        ))
        except Exception as e:
            print(f"ARP table error: {e}")
        
        return devices
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP address to hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _lookup_vendor(self, mac: str) -> Optional[str]:
        """Look up vendor from MAC address using OUI database."""
        # Use our local OUI database lookup
        vendor = oui_lookup_vendor(mac)
        if vendor:
            return vendor
        
        # Fallback to embedded OUI prefixes for common vendors
        mac_normalized = mac.lower().replace('-', ':')
        prefix = mac_normalized[:8]  # First 8 chars (e.g., "00:11:22")
        if prefix in FALLBACK_OUI:
            return FALLBACK_OUI[prefix]
        
        return None
