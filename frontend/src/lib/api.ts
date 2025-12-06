import { Device, DeviceListResponse, DashboardStats, ScanEvent, ScanSession } from "@/types";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async fetch<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  // Devices
  async getDevices(params?: {
    skip?: number;
    limit?: number;
    online_only?: boolean;
    search?: string;
  }): Promise<DeviceListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.skip) searchParams.set("skip", params.skip.toString());
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.online_only) searchParams.set("online_only", "true");
    if (params?.search) searchParams.set("search", params.search);

    const query = searchParams.toString();
    return this.fetch<DeviceListResponse>(
      `/api/devices${query ? `?${query}` : ""}`
    );
  }

  async getDevice(id: number): Promise<Device> {
    return this.fetch<Device>(`/api/devices/${id}`);
  }

  async updateDevice(
    id: number,
    data: Partial<Device>
  ): Promise<Device> {
    return this.fetch<Device>(`/api/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  }

  async deleteDevice(id: number): Promise<void> {
    await this.fetch(`/api/devices/${id}`, { method: "DELETE" });
  }

  async getDeviceEvents(id: number, limit = 50): Promise<ScanEvent[]> {
    return this.fetch<ScanEvent[]>(
      `/api/devices/${id}/events?limit=${limit}`
    );
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    return this.fetch<DashboardStats>("/api/dashboard/stats");
  }

  // Scanning
  async triggerScan(): Promise<{
    success: boolean;
    message: string;
    devices_found?: number;
    devices_online?: number;
    devices_new?: number;
  }> {
    return this.fetch("/api/scan/trigger", { method: "POST" });
  }

  async getScanSessions(limit = 20): Promise<ScanSession[]> {
    return this.fetch<ScanSession[]>(`/api/scan/sessions?limit=${limit}`);
  }
}

export const api = new ApiClient(API_URL);
