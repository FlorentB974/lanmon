export interface Device {
  id: number;
  mac_address: string;
  ip_address: string | null;
  hostname: string | null;
  vendor: string | null;
  device_type: string | null;
  custom_name: string | null;
  notes: string | null;
  is_online: boolean;
  is_favorite: boolean;
  is_known: boolean;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  open_ports: string | null;
  network_interface: string | null;
  model: string | null;
  manufacturer: string | null;
  friendly_name: string | null;
  services: string | null;
}

export interface DeviceListResponse {
  devices: Device[];
  total: number;
  skip: number;
  limit: number;
}

export interface ScanEvent {
  id: number;
  device_id: number;
  event_type: "connected" | "disconnected" | "ip_changed";
  ip_address: string | null;
  old_ip_address: string | null;
  timestamp: string;
  response_time: number | null;
  scan_method: string | null;
}

export interface ScanSession {
  id: number;
  started_at: string;
  completed_at: string | null;
  status: "running" | "completed" | "failed";
  devices_found: number;
  devices_online: number;
  devices_new: number;
  subnet: string | null;
  scan_method: string | null;
  error_message: string | null;
}

export interface DashboardStats {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  new_devices: number;
  active_last_24h: number;
  events_last_24h: number;
  last_scan_time: string | null;
}

export interface WebSocketMessage {
  type: string;
  data: Record<string, unknown>;
}
