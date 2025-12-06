from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timedelta

from ..db.database import get_db
from ..db.models import Device, ScanEvent, ScanSession
from .schemas import (
    DeviceResponse,
    DeviceUpdate,
    DeviceListResponse,
    ScanEventResponse,
    ScanSessionResponse,
    ScanTriggerResponse,
    DashboardStats
)

router = APIRouter()


@router.get("/devices", response_model=DeviceListResponse)
async def get_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    online_only: bool = Query(False),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """Get all devices with optional filtering."""
    query = select(Device)
    
    if online_only:
        query = query.where(Device.is_online == True)
    
    if search:
        search_term = f"%{search}%"
        query = query.where(
            (Device.hostname.ilike(search_term)) |
            (Device.custom_name.ilike(search_term)) |
            (Device.ip_address.ilike(search_term)) |
            (Device.mac_address.ilike(search_term)) |
            (Device.vendor.ilike(search_term))
        )
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)
    
    # Get devices with pagination
    query = query.order_by(desc(Device.is_online), desc(Device.last_seen))
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    devices = result.scalars().all()
    
    return DeviceListResponse(
        devices=[DeviceResponse.model_validate(d) for d in devices],
        total=total,
        skip=skip,
        limit=limit
    )


@router.get("/devices/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific device by ID."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return DeviceResponse.model_validate(device)


@router.get("/devices/mac/{mac_address}", response_model=DeviceResponse)
async def get_device_by_mac(mac_address: str, db: AsyncSession = Depends(get_db)):
    """Get a specific device by MAC address."""
    result = await db.execute(
        select(Device).where(Device.mac_address == mac_address.lower())
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return DeviceResponse.model_validate(device)


@router.patch("/devices/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int,
    device_update: DeviceUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update a device's custom fields."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    update_data = device_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(device, key, value)
    
    device.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(device)
    
    return DeviceResponse.model_validate(device)


@router.delete("/devices/{device_id}")
async def delete_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a device and its history."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    await db.delete(device)
    await db.commit()
    
    return {"message": "Device deleted successfully"}


@router.get("/devices/{device_id}/events", response_model=list[ScanEventResponse])
async def get_device_events(
    device_id: int,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db)
):
    """Get scan events for a specific device."""
    result = await db.execute(
        select(ScanEvent)
        .where(ScanEvent.device_id == device_id)
        .order_by(desc(ScanEvent.timestamp))
        .limit(limit)
    )
    events = result.scalars().all()
    
    return [ScanEventResponse.model_validate(e) for e in events]


@router.get("/scan/sessions", response_model=list[ScanSessionResponse])
async def get_scan_sessions(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    """Get recent scan sessions."""
    result = await db.execute(
        select(ScanSession)
        .order_by(desc(ScanSession.started_at))
        .limit(limit)
    )
    sessions = result.scalars().all()
    
    return [ScanSessionResponse.model_validate(s) for s in sessions]


@router.post("/scan/trigger", response_model=ScanTriggerResponse)
async def trigger_scan(
    deep_scan: bool = Query(True, description="Perform enhanced device info gathering"),
    db: AsyncSession = Depends(get_db)
):
    """Trigger an immediate network scan."""
    from ..main import scanner
    
    try:
        result = await scanner.perform_scan(deep_scan=deep_scan)
        return ScanTriggerResponse(
            success=True,
            message="Scan completed successfully",
            **result
        )
    except Exception as e:
        return ScanTriggerResponse(
            success=False,
            message=f"Scan failed: {str(e)}",
            session_id=0,
            devices_found=0,
            devices_online=0,
            devices_new=0
        )


@router.post("/devices/{device_id}/rescan", response_model=DeviceResponse)
async def rescan_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Rescan a specific device to gather enhanced information."""
    from ..scanner.device_info import DeviceInfoScanner
    import json
    
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if not device.ip_address:
        raise HTTPException(status_code=400, detail="Device has no IP address")
    
    # Perform enhanced scan
    scanner = DeviceInfoScanner(timeout=3.0)
    enhanced_info = await scanner.get_device_info(device.ip_address, device.mac_address)
    
    # Update device with enhanced info
    if enhanced_info.primary_hostname and (not device.hostname or device.hostname.endswith('.local')):
        device.hostname = enhanced_info.primary_hostname
    
    if enhanced_info.manufacturer and not device.vendor:
        device.vendor = enhanced_info.manufacturer
    elif enhanced_info.vendor and not device.vendor:
        device.vendor = enhanced_info.vendor
    
    if enhanced_info.detected_type:
        device.device_type = enhanced_info.detected_type
    
    if enhanced_info.open_ports:
        device.open_ports = json.dumps(enhanced_info.open_ports)
    
    device.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(device)
    
    return DeviceResponse.model_validate(device)


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get dashboard statistics."""
    # Total devices
    total_devices = await db.scalar(select(func.count()).select_from(Device))
    
    # Online devices
    online_devices = await db.scalar(
        select(func.count()).select_from(Device).where(Device.is_online == True)
    )
    
    # New devices (unknown)
    new_devices = await db.scalar(
        select(func.count()).select_from(Device).where(Device.is_known == False)
    )
    
    # Devices seen in last 24 hours
    last_24h = datetime.utcnow() - timedelta(hours=24)
    active_24h = await db.scalar(
        select(func.count()).select_from(Device).where(Device.last_seen >= last_24h)
    )
    
    # Recent events
    recent_events = await db.scalar(
        select(func.count())
        .select_from(ScanEvent)
        .where(ScanEvent.timestamp >= last_24h)
    )
    
    # Last scan
    last_scan_result = await db.execute(
        select(ScanSession)
        .where(ScanSession.status == "completed")
        .order_by(desc(ScanSession.completed_at))
        .limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()
    
    return DashboardStats(
        total_devices=total_devices or 0,
        online_devices=online_devices or 0,
        offline_devices=(total_devices or 0) - (online_devices or 0),
        new_devices=new_devices or 0,
        active_last_24h=active_24h or 0,
        events_last_24h=recent_events or 0,
        last_scan_time=last_scan.completed_at if last_scan else None
    )
