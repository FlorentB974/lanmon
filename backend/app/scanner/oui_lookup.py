"""
OUI (Organizationally Unique Identifier) lookup for MAC address vendor identification.
Uses a local JSON database from maclookup.app
"""

import json
import os
from typing import Optional, Dict
from pathlib import Path

# Path to the OUI database
OUI_DATABASE_PATH = Path(__file__).parent / "oui_database.json"

# In-memory cache for the OUI database
_oui_cache: Dict[str, str] = {}
_cache_loaded = False


def _normalize_mac(mac: str) -> str:
    """Normalize a MAC address or registry prefix without separators."""
    # Remove separators and convert to uppercase
    mac_clean = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    return mac_clean


def _load_oui_database():
    """Load the OUI database into memory."""
    global _oui_cache, _cache_loaded
    
    if _cache_loaded:
        return
    
    if not OUI_DATABASE_PATH.exists():
        print(f"⚠️ OUI database not found at {OUI_DATABASE_PATH}")
        _cache_loaded = True
        return
    
    try:
        with open(OUI_DATABASE_PATH, 'r') as f:
            data = json.load(f)
        
        # Build lookup dictionary
        # Format: [{"macPrefix":"00:00:0C","vendorName":"Cisco Systems, Inc",...}, ...]
        for entry in data:
            prefix = entry.get('macPrefix', '')
            vendor = entry.get('vendorName', '')
            if prefix and vendor:
                # Normalize prefix (remove colons, uppercase)
                normalized = prefix.upper().replace(':', '').replace('-', '')
                _oui_cache[normalized] = vendor
        
        print(f"✅ OUI database loaded: {len(_oui_cache)} vendors")
        _cache_loaded = True
        
    except json.JSONDecodeError as e:
        print(f"⚠️ Failed to parse OUI database: {e}")
        _cache_loaded = True
    except Exception as e:
        print(f"⚠️ Failed to load OUI database: {e}")
        _cache_loaded = True


def lookup_vendor(mac: str) -> Optional[str]:
    """
    Look up the vendor for a MAC address.
    
    Args:
        mac: MAC address in any format (e.g., "00:11:22:33:44:55", "00-11-22-33-44-55", "001122334455")
    
    Returns:
        Vendor name or None if not found
    """
    # Ensure database is loaded
    if not _cache_loaded:
        _load_oui_database()
    
    if not mac:
        return None
    
    mac_clean = _normalize_mac(mac)
    if len(mac_clean) != 12 or any(character not in "0123456789ABCDEF" for character in mac_clean):
        return None

    # Locally administered addresses are privacy/container addresses. Their
    # first bytes are not an IEEE assignment and must not produce an OUI hit.
    if int(mac_clean[:2], 16) & 0x02:
        return None

    # Prefer the most-specific MA-S/MA-M assignment before the older 24-bit
    # MA-L prefix. Checking MA-L first made every more-specific record dead.
    for length in range(min(len(mac_clean), 12), 5, -1):
        vendor = _oui_cache.get(mac_clean[:length])
        if vendor:
            return vendor
    
    return None


def get_vendor_count() -> int:
    """Get the number of vendors in the database."""
    if not _cache_loaded:
        _load_oui_database()
    return len(_oui_cache)


# Pre-load the database on module import
_load_oui_database()
