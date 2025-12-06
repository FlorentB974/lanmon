from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional


class DeviceBase(BaseModel):
    """Base device schema."""
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    custom_name: Optional[str] = None
    notes: Optional[str] = None


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
