from pydantic import BaseModel, ConfigDict, Field, field_serializer
from datetime import datetime
from typing import Literal, Optional


class IdentificationEvidence(BaseModel):
    source: str
    summary: str
    value: str
    strength: Literal["weak", "medium", "strong"]


class IdentificationResult(BaseModel):
    version: int = 1
    label: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[Literal["low", "medium", "high"]] = None
    score: int = 0
    ambiguous: bool = False
    evidence: list[IdentificationEvidence] = Field(default_factory=list)
    probes: dict[str, str] = Field(default_factory=dict)
    identified_at: datetime


class DeviceBase(BaseModel):
    """Base device schema."""
    mac_address: str
    mac_aliases: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None
    friendly_name: Optional[str] = None
    custom_name: Optional[str] = None
    notes: Optional[str] = None
    services: Optional[str] = None
    discovery_info: Optional[str] = None


class DeviceResponse(DeviceBase):
    """Device response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    is_online: bool
    is_favorite: bool
    is_known: bool
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    open_ports: Optional[str] = None
    network_interface: Optional[str] = None
    is_private_mac: bool = False
    mac_rotation_detected: bool = False
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    friendly_name: Optional[str] = None
    services: Optional[str] = None
    discovery_info: Optional[str] = None
    identification: Optional[IdentificationResult] = None
    effective_device_type: Optional[str] = None
    last_deep_scan_at: Optional[datetime] = None

    @field_serializer('first_seen', 'last_seen', 'created_at', 'updated_at', 'last_deep_scan_at')
    def serialize_datetime(self, dt: Optional[datetime], _info) -> Optional[str]:
        """Serialize datetime to ISO 8601 format with timezone."""
        if dt:
            # Ensure timezone-aware, add Z suffix for UTC
            if dt.tzinfo is None:
                # If somehow a naive datetime got through, treat it as UTC
                return dt.isoformat() + 'Z'
            return dt.isoformat().replace('+00:00', 'Z')
        return None


class DeviceUpdate(BaseModel):
    """Device update schema."""
    custom_name: Optional[str] = None
    device_type: Optional[str] = None
    notes: Optional[str] = None
    is_favorite: Optional[bool] = None
    is_known: Optional[bool] = None


class DeviceListResponse(BaseModel):
    """Device list response with pagination."""
    devices: list[DeviceResponse]
    total: int
    skip: int
    limit: int


class ScanEventResponse(BaseModel):
    """Scan event response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    device_id: int
    event_type: str
    ip_address: Optional[str] = None
    old_ip_address: Optional[str] = None
    timestamp: datetime
    response_time: Optional[float] = None
    scan_method: Optional[str] = None

    @field_serializer('timestamp')
    def serialize_datetime(self, dt: datetime, _info) -> str:
        """Serialize datetime to ISO 8601 format with timezone."""
        if dt:
            if dt.tzinfo is None:
                return dt.isoformat() + 'Z'
            return dt.isoformat().replace('+00:00', 'Z')
        return None


class ScanSessionResponse(BaseModel):
    """Scan session response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    devices_found: int
    devices_online: int
    devices_new: int
    subnet: Optional[str] = None
    scan_method: Optional[str] = None
    error_message: Optional[str] = None

    @field_serializer('started_at', 'completed_at')
    def serialize_datetime(self, dt: datetime, _info) -> str:
        """Serialize datetime to ISO 8601 format with timezone."""
        if dt:
            if dt.tzinfo is None:
                return dt.isoformat() + 'Z'
            return dt.isoformat().replace('+00:00', 'Z')
        return None


class ScanTriggerResponse(BaseModel):
    """Scan trigger response schema."""
    success: bool
    message: str
    session_id: Optional[int] = None
    devices_found: Optional[int] = None
    devices_online: Optional[int] = None
    devices_new: Optional[int] = None
    subnet: Optional[str] = None


class DashboardStats(BaseModel):
    """Dashboard statistics schema."""
    total_devices: int
    online_devices: int
    offline_devices: int
    new_devices: int
    active_last_24h: int
    events_last_24h: int
    last_scan_time: Optional[datetime] = None

    @field_serializer('last_scan_time')
    def serialize_datetime(self, dt: datetime, _info) -> str:
        """Serialize datetime to ISO 8601 format with timezone."""
        if dt:
            if dt.tzinfo is None:
                return dt.isoformat() + 'Z'
            return dt.isoformat().replace('+00:00', 'Z')
        return None
