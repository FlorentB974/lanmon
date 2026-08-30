import json

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


class Device(Base):
    """Device model representing a network device."""
    
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String(17), unique=True, index=True, nullable=False)
    # JSON array of previously observed MAC addresses. Phones and laptops can
    # rotate their private Wi-Fi address, so MAC alone is not a durable identity.
    mac_aliases = Column(Text, default="[]")
    ip_address = Column(String(45), index=True)  # IPv6 compatible
    hostname = Column(String(255))
    vendor = Column(String(255))
    manufacturer = Column(String(255))  # Device manufacturer (from mDNS)
    device_type = Column(String(100))  # router, computer, phone, iot, etc.
    model = Column(String(255))  # Device model (e.g., MacBookPro18,3, AppleTV6,2)
    friendly_name = Column(String(255))  # User-friendly name from mDNS
    custom_name = Column(String(255))
    notes = Column(Text)
    services = Column(Text)  # JSON string of discovered services
    discovery_info = Column(Text)  # JSON details from mDNS, SSDP, NetBIOS and HTTP
    identification_data = Column("identification", Text)
    
    # Status
    is_online = Column(Boolean, default=False)
    is_favorite = Column(Boolean, default=False)
    is_known = Column(Boolean, default=True)  # Known vs unknown/new device
    missed_scans = Column(Integer, default=0)  # Number of consecutive scans where device was not seen
    
    # Timestamps
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    # Unlike updated_at, this only changes after active fingerprint probes.
    last_deep_scan_at = Column(DateTime)
    
    # Network info
    open_ports = Column(Text)  # JSON string of open ports
    network_interface = Column(String(50))

    @property
    def is_private_mac(self) -> bool:
        """Whether the active MAC is a locally administered unicast address.

        Modern phones and laptops commonly use this bit for their private
        Wi-Fi address. It is only a hint by itself; ``mac_rotation_detected``
        requires that we have also observed a different address for the same
        logical device.
        """
        try:
            mac = (self.mac_address or "").strip().lower().replace("-", ":").replace(".", "")
            compact = mac.replace(":", "")
            first_octet = int(compact[:2], 16)
            if len(compact) != 12:
                return False
            return (first_octet & 0x03) == 0x02
        except (ValueError, IndexError):
            return False

    @property
    def mac_rotation_detected(self) -> bool:
        """Whether this device has been grouped across multiple MACs."""
        try:
            aliases = json.loads(self.mac_aliases or "[]")
            return isinstance(aliases, list) and any(aliases)
        except (TypeError, ValueError):
            return False

    @property
    def identification(self):
        """Return the scanner's typed identity suggestion."""
        try:
            value = json.loads(self.identification_data or "null")
            return value if isinstance(value, dict) else None
        except (TypeError, ValueError):
            return None

    def set_identification(self, value) -> None:
        self.identification_data = json.dumps(value, sort_keys=True) if value else None

    @property
    def effective_device_type(self):
        """Prefer the user's category, then the scanner suggestion."""
        if self.device_type:
            return self.device_type
        identification = self.identification
        return identification.get("category") if identification else None
    
    # Relationships
    scan_events = relationship("ScanEvent", back_populates="device", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Device(mac={self.mac_address}, ip={self.ip_address}, hostname={self.hostname})>"


class ScanEvent(Base):
    """Scan event model for tracking device connection history."""
    
    __tablename__ = "scan_events"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    event_type = Column(String(20), nullable=False)  # connected, disconnected, ip_changed
    ip_address = Column(String(45))
    old_ip_address = Column(String(45))  # For IP change events
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Additional scan data
    response_time = Column(Float)  # in milliseconds
    scan_method = Column(String(50))  # arp, nmap, ping, etc.
    
    # Relationships
    device = relationship("Device", back_populates="scan_events")
    
    def __repr__(self):
        return f"<ScanEvent(device_id={self.device_id}, type={self.event_type}, time={self.timestamp})>"


class ScanSession(Base):
    """Scan session model for tracking complete network scans."""
    
    __tablename__ = "scan_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime)
    status = Column(String(20), default="running")  # running, completed, failed
    devices_found = Column(Integer, default=0)
    devices_online = Column(Integer, default=0)
    devices_new = Column(Integer, default=0)
    subnet = Column(String(50))
    scan_method = Column(String(50))
    error_message = Column(Text)
    
    def __repr__(self):
        return f"<ScanSession(id={self.id}, status={self.status}, devices={self.devices_found})>"
