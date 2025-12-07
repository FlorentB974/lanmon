from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional
from datetime import datetime, timedelta, timezone
import ipaddress

from ..db.database import get_db
from ..db.models import Device, ScanEvent, ScanSession
from ..core.config import settings
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
    
    # Filter by configured subnet if DEFAULT_SUBNET is set
    if settings.DEFAULT_SUBNET:
        try:
            network = ipaddress.ip_network(settings.DEFAULT_SUBNET, strict=False)
            # Filter devices to only those in the configured subnet
            query = query.where(Device.ip_address != None)
            result = await db.execute(query)
            all_devices = result.scalars().all()
            
            # Filter in Python since SQL doesn't have built-in CIDR matching
            devices_in_subnet = []
            for device in all_devices:
                if device.ip_address:
                    try:
                        ip = ipaddress.ip_address(device.ip_address)
                        if ip in network:
                            devices_in_subnet.append(device)
                    except ValueError:
                        pass
            
            # Re-apply other filters
            if online_only:
                devices_in_subnet = [d for d in devices_in_subnet if d.is_online]
            
            if search:
                search_term = search.lower()
                devices_in_subnet = [
                    d for d in devices_in_subnet
                    if (d.hostname and search_term in d.hostname.lower()) or
                       (d.custom_name and search_term in d.custom_name.lower()) or
                       (d.ip_address and search_term in d.ip_address.lower()) or
                       (d.mac_address and search_term in d.mac_address.lower()) or
                       (d.vendor and search_term in d.vendor.lower())
                ]
            
            # Sort
            devices_in_subnet.sort(key=lambda d: (not d.is_online, d.last_seen or datetime.min), reverse=True)
            
            total = len(devices_in_subnet)
            devices = devices_in_subnet[skip:skip+limit]
            
            return DeviceListResponse(
                devices=[DeviceResponse.model_validate(d) for d in devices],
                total=total,
                skip=skip,
                limit=limit
            )
        except Exception as e:
            print(f"Error filtering by subnet: {e}")
            # Fall through to normal query
    
    # Normal query without subnet filtering
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
    from sqlalchemy.exc import OperationalError
    import asyncio
    
    # Retry logic for database locks
    max_retries = 3
    for attempt in range(max_retries):
        try:
            result = await db.execute(select(Device).where(Device.id == device_id))
            device = result.scalar_one_or_none()
            
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            
            update_data = device_update.model_dump(exclude_unset=True)
            for key, value in update_data.items():
                setattr(device, key, value)
            
            device.updated_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(device)
            
            return DeviceResponse.model_validate(device)
            
        except OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                await db.rollback()
                wait_time = 0.5 * (2 ** attempt)  # Exponential backoff
                await asyncio.sleep(wait_time)
                continue
            else:
                await db.rollback()
                raise HTTPException(
                    status_code=503,
                    detail="Database is temporarily busy, please try again"
                )


@router.delete("/devices/{device_id}")
async def delete_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a device and its history."""
    from sqlalchemy.exc import OperationalError
    import asyncio
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            result = await db.execute(select(Device).where(Device.id == device_id))
            device = result.scalar_one_or_none()
            
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            
            await db.delete(device)
            await db.commit()
            
            return {"message": "Device deleted successfully"}
            
        except OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                await db.rollback()
                wait_time = 0.5 * (2 ** attempt)
                await asyncio.sleep(wait_time)
                continue
            else:
                await db.rollback()
                raise HTTPException(
                    status_code=503,
                    detail="Database is temporarily busy, please try again"
                )


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
    from sqlalchemy.exc import OperationalError
    import json
    import asyncio
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
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
            
            device.updated_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(device)
            
            return DeviceResponse.model_validate(device)
            
        except OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                await db.rollback()
                wait_time = 0.5 * (2 ** attempt)
                await asyncio.sleep(wait_time)
                continue
            else:
                await db.rollback()
                raise HTTPException(
                    status_code=503,
                    detail="Database is temporarily busy, please try again"
                )


@router.delete("/devices/cleanup-subnet")
async def cleanup_devices_outside_subnet(db: AsyncSession = Depends(get_db)):
    """Delete all devices that are outside the configured subnet."""
    if not settings.DEFAULT_SUBNET:
        raise HTTPException(
            status_code=400, 
            detail="No DEFAULT_SUBNET configured. Cannot cleanup."
        )
    
    try:
        network = ipaddress.ip_network(settings.DEFAULT_SUBNET, strict=False)
        
        # Get all devices
        result = await db.execute(select(Device))
        all_devices = result.scalars().all()
        
        devices_to_delete = []
        for device in all_devices:
            if device.ip_address:
                try:
                    ip = ipaddress.ip_address(device.ip_address)
                    if ip not in network:
                        devices_to_delete.append(device)
                except ValueError:
                    # Invalid IP, delete it
                    devices_to_delete.append(device)
            else:
                # No IP address, keep it for now
                pass
        
        # Delete devices outside subnet
        deleted_count = 0
        for device in devices_to_delete:
            await db.delete(device)
            deleted_count += 1
        
        await db.commit()
        
        return {
            "message": f"Deleted {deleted_count} devices outside subnet {settings.DEFAULT_SUBNET}",
            "deleted_count": deleted_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error cleaning up devices: {str(e)}")


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
    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
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
