"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence } from "framer-motion";
import {
  Activity,
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Camera,
  Check,
  ChevronRight,
  Clock,
  Cpu,
  HelpCircle,
  Laptop,
  Monitor,
  MoreHorizontal,
  Printer,
  RefreshCw,
  Router,
  Search,
  Server,
  Smartphone,
  Speaker,
  Star,
  Tablet,
  Trash2,
  Tv,
  Wifi,
  WifiOff,
} from "lucide-react";
import { api } from "@/lib/api";
import { useWebSocket } from "@/lib/useWebSocket";
import { Device, DashboardStats } from "@/types";
import { cn, formatMacAddress, getDeviceIcon, timeAgo } from "@/lib/utils";
import DeviceModal from "@/components/DeviceModal";

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  router: Router,
  smartphone: Smartphone,
  tablet: Tablet,
  laptop: Laptop,
  monitor: Monitor,
  tv: Tv,
  printer: Printer,
  camera: Camera,
  speaker: Speaker,
  cpu: Cpu,
  "help-circle": HelpCircle,
};

type Filter = "all" | "online" | "offline" | "new" | "known";
type QuickAction = "favorite" | "known";
type BulkAction = QuickAction | "delete";
type SortKey = "device" | "ip" | "status" | "vendor" | "lastSeen";
type SortDirection = "asc" | "desc";

interface SortConfig {
  key: SortKey;
  direction: SortDirection;
}

function deviceName(device: Device): string {
  return device.custom_name || device.friendly_name || device.hostname || "Unknown device";
}

function parseMacAliases(device: Device): string[] {
  if (!device.mac_aliases) return [];
  try {
    const aliases = JSON.parse(device.mac_aliases);
    return Array.isArray(aliases) ? aliases : [];
  } catch {
    return [];
  }
}

function parseStringArray(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function compareText(a: string | null | undefined, b: string | null | undefined, direction: SortDirection): number {
  const aValue = a?.trim() || "";
  const bValue = b?.trim() || "";
  const aMissing = aValue.length === 0;
  const bMissing = bValue.length === 0;

  // Keep unknown or unavailable values at the bottom in either direction.
  if (aMissing || bMissing) {
    if (aMissing && bMissing) return 0;
    return aMissing ? 1 : -1;
  }

  return direction === "asc"
    ? aValue.localeCompare(bValue, undefined, { numeric: true, sensitivity: "base" })
    : bValue.localeCompare(aValue, undefined, { numeric: true, sensitivity: "base" });
}

function compareDevices(a: Device, b: Device, sortConfig: SortConfig): number {
  const { key, direction } = sortConfig;
  let comparison = 0;

  switch (key) {
    case "device":
      comparison = compareText(deviceName(a), deviceName(b), direction);
      break;
    case "ip":
      comparison = compareText(a.ip_address, b.ip_address, direction);
      break;
    case "status":
      comparison = direction === "asc"
        ? Number(a.is_online) - Number(b.is_online)
        : Number(b.is_online) - Number(a.is_online);
      break;
    case "vendor":
      comparison = compareText(
        a.manufacturer || a.vendor || "",
        b.manufacturer || b.vendor || "",
        direction,
      );
      break;
    case "lastSeen":
      comparison = direction === "asc"
        ? new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime()
        : new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      break;
  }

  return comparison || a.id - b.id;
}

function SortableHeader({
  label,
  sortKey,
  sortConfig,
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  sortConfig: SortConfig | null;
  onSort: (sortKey: SortKey) => void;
}) {
  const isActive = sortConfig?.key === sortKey;
  const SortIcon = !isActive
    ? ArrowUpDown
    : sortConfig.direction === "asc" ? ArrowUp : ArrowDown;

  return (
    <th
      scope="col"
      aria-sort={!isActive ? "none" : sortConfig.direction === "asc" ? "ascending" : "descending"}
      className="px-3 py-3 font-medium"
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="group/header inline-flex items-center gap-1.5 text-left transition-colors hover:text-slate-200"
        title={`Sort by ${label}${isActive ? ` (${sortConfig.direction === "asc" ? "ascending" : "descending"})` : ""}`}
      >
        {label}
        <SortIcon className={cn("h-3.5 w-3.5", isActive ? "text-brand-400" : "text-slate-600 group-hover/header:text-slate-400")} />
      </button>
    </th>
  );
}

function SummaryMetric({ label, value, tone }: { label: string; value: string | number; tone: string }) {
  return (
    <div className="flex items-center gap-3 px-5 py-1 first:pl-1">
      <span className={cn("h-2 w-2 rounded-full", tone)} />
      <div>
        <p className="text-xl font-semibold tracking-tight text-white">{value}</p>
        <p className="text-xs text-slate-500">{label}</p>
      </div>
    </div>
  );
}

export default function Home() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [sortConfig, setSortConfig] = useState<SortConfig | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<Set<number>>(new Set());
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [bulkActionLoading, setBulkActionLoading] = useState<BulkAction | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const selectAllRef = useRef<HTMLInputElement>(null);
  const refreshPromiseRef = useRef<Promise<void> | null>(null);
  const { isConnected, lastMessage } = useWebSocket();

  const fetchData = useCallback(async () => {
    if (refreshPromiseRef.current) return refreshPromiseRef.current;

    const refresh = (async () => {
      try {
        const [devicesRes, statsRes, sessions] = await Promise.all([
          api.getDevices({ limit: 500 }),
          api.getDashboardStats(),
          api.getScanSessions(5),
        ]);
        setDevices(devicesRes.devices);
        setSelectedDeviceIds((current) => {
          const availableIds = new Set(devicesRes.devices.map((device) => device.id));
          const next = new Set<number>();
          current.forEach((deviceId) => {
            if (availableIds.has(deviceId)) next.add(deviceId);
          });
          return next.size === current.size ? current : next;
        });
        setStats(statsRes);
        setScanning(sessions.some((session) => session.status === "running"));
        setSelectedDevice((current) => {
          if (!current) return null;
          return devicesRes.devices.find((device) => device.id === current.id) || null;
        });
      } catch (error) {
        console.error("Failed to fetch data:", error);
      } finally {
        setLoading(false);
        refreshPromiseRef.current = null;
      }
    })();

    refreshPromiseRef.current = refresh;
    return refresh;
  }, []);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (!lastMessage) return;

    if (lastMessage.type === "scan_started") {
      setScanning(true);
      setScanError(null);
    }

    if (lastMessage.type === "scan_completed" || lastMessage.type === "scan_failed") {
      setScanning(false);
      void fetchData();
    }

    if (lastMessage.type === "device_identified") {
      void fetchData();
    }
  }, [lastMessage, fetchData]);

  // The WebSocket is the fast path, while this low-frequency check prevents
  // a disconnected browser from leaving the scan indicator stuck forever.
  useEffect(() => {
    if (!scanning) return;
    const interval = window.setInterval(() => { void fetchData(); }, 5000);
    return () => window.clearInterval(interval);
  }, [scanning, fetchData]);

  const updateDeviceInState = useCallback((updated: Device) => {
    setDevices((current) => current.map((device) => device.id === updated.id ? updated : device));
    setSelectedDevice((current) => current?.id === updated.id ? updated : current);
  }, []);

  const handleQuickAction = async (device: Device, action: QuickAction) => {
    const actionKey = `${action}-${device.id}`;
    setActionLoading(actionKey);
    setActionError(null);
    try {
      const updated = await api.updateDevice(device.id, action === "favorite"
        ? { is_favorite: !device.is_favorite }
        : { is_known: true });
      updateDeviceInState(updated);
    } catch (error) {
      console.error(`Failed to update device ${action}:`, error);
      setActionError("That change could not be saved. It will be safe to retry.");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteQuickAction = async (device: Device) => {
    if (!window.confirm(`Delete ${deviceName(device)}? This will remove all device data and history.`)) return;

    const actionKey = `delete-${device.id}`;
    setActionLoading(actionKey);
    setActionError(null);
    try {
      await api.deleteDevice(device.id);
      setDevices((current) => current.filter((currentDevice) => currentDevice.id !== device.id));
      setSelectedDevice((current) => current?.id === device.id ? null : current);
      setSelectedDeviceIds((current) => {
        const next = new Set(current);
        next.delete(device.id);
        return next;
      });
      void fetchData();
    } catch (error) {
      console.error("Failed to delete device:", error);
      setActionError("That device could not be deleted. It will be safe to retry.");
    } finally {
      setActionLoading(null);
    }
  };

  const handleBulkQuickAction = async (action: QuickAction) => {
    const selectedDevices = devices.filter((device) => selectedDeviceIds.has(device.id));
    if (selectedDevices.length === 0) return;

    const favoriteValue = action === "favorite"
      ? !selectedDevices.every((device) => device.is_favorite)
      : undefined;
    setBulkActionLoading(action);
    setActionError(null);

    const results = await Promise.allSettled(
      selectedDevices.map((device) => api.updateDevice(
        device.id,
        action === "favorite" ? { is_favorite: favoriteValue } : { is_known: true },
      )),
    );
    const failedIds = new Set<number>();

    results.forEach((result, index) => {
      if (result.status === "fulfilled") {
        updateDeviceInState(result.value);
      } else {
        failedIds.add(selectedDevices[index].id);
      }
    });

    setSelectedDeviceIds(failedIds);
    if (failedIds.size > 0) {
      setActionError(`${failedIds.size} device${failedIds.size === 1 ? "" : "s"} could not be updated. You can retry the selection.`);
    }
    setBulkActionLoading(null);
    void fetchData();
  };

  const handleBulkDelete = async () => {
    const selectedDevices = devices.filter((device) => selectedDeviceIds.has(device.id));
    if (selectedDevices.length === 0) return;
    const deviceLabel = selectedDevices.length === 1 ? "this device" : `these ${selectedDevices.length} devices`;

    if (!window.confirm(`Delete ${deviceLabel}? This will remove all device data and history.`)) return;

    setBulkActionLoading("delete");
    setActionError(null);
    const results = await Promise.allSettled(selectedDevices.map((device) => api.deleteDevice(device.id)));
    const deletedIds = new Set<number>();
    const failedIds = new Set<number>();

    results.forEach((result, index) => {
      if (result.status === "fulfilled") {
        deletedIds.add(selectedDevices[index].id);
      } else {
        failedIds.add(selectedDevices[index].id);
      }
    });

    setDevices((current) => current.filter((device) => !deletedIds.has(device.id)));
    setSelectedDevice((current) => current && deletedIds.has(current.id) ? null : current);
    setSelectedDeviceIds(failedIds);
    if (failedIds.size > 0) {
      setActionError(`${failedIds.size} device${failedIds.size === 1 ? "" : "s"} could not be deleted. You can retry the selection.`);
    }
    setBulkActionLoading(null);
    void fetchData();
  };

  const handleScan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const result = await api.triggerScan();
      if (!result.success) throw new Error(result.message);
    } catch (error) {
      console.error("Scan failed to start:", error);
      setScanning(false);
      setScanError(error instanceof Error ? error.message : "The scan could not be started.");
    }
  };

  const filteredDevices = devices
    // Keep the existing ID order until the user chooses a sort column, so scans
    // can update status and metadata without making the user's place jump.
    .slice()
    .filter((device) => {
      const searchLower = search.toLowerCase();
      const aliases = parseMacAliases(device).join(" ");
      const matchesSearch = !search || [
        deviceName(device),
        device.hostname,
        device.ip_address,
        device.mac_address,
        aliases,
        device.vendor,
        device.manufacturer,
        device.model,
        device.identification?.label,
        device.identification?.category,
        device.services,
        device.discovery_info,
      ].some((value) => value?.toLowerCase().includes(searchLower));

      const matchesFilter = filter === "all"
        || (filter === "online" && device.is_online)
        || (filter === "offline" && !device.is_online)
        || (filter === "new" && !device.is_known)
        || (filter === "known" && device.is_known);

      return matchesSearch && matchesFilter;
    })
    .sort((a, b) => sortConfig ? compareDevices(a, b, sortConfig) : a.id - b.id);

  const selectedDevices = devices.filter((device) => selectedDeviceIds.has(device.id));
  const allVisibleSelected = filteredDevices.length > 0 && filteredDevices.every((device) => selectedDeviceIds.has(device.id));
  const someVisibleSelected = filteredDevices.some((device) => selectedDeviceIds.has(device.id));
  const allSelectedAreFavorites = selectedDevices.length > 0 && selectedDevices.every((device) => device.is_favorite);

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = someVisibleSelected && !allVisibleSelected;
    }
  }, [allVisibleSelected, someVisibleSelected]);

  const toggleDeviceSelection = (deviceId: number) => {
    setSelectedDeviceIds((current) => {
      const next = new Set(current);
      if (next.has(deviceId)) {
        next.delete(deviceId);
      } else {
        next.add(deviceId);
      }
      return next;
    });
  };

  const toggleVisibleSelection = () => {
    setSelectedDeviceIds((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        filteredDevices.forEach((device) => next.delete(device.id));
      } else {
        filteredDevices.forEach((device) => next.add(device.id));
      }
      return next;
    });
  };

  const handleSort = (sortKey: SortKey) => {
    setSortConfig((current) => current?.key === sortKey
      ? { key: sortKey, direction: current.direction === "asc" ? "desc" : "asc" }
      : { key: sortKey, direction: "asc" });
  };

  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-[1600px] px-4 py-6 md:px-8 md:py-8">
        <header className="mb-7 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-500/15 text-brand-400">
                <Activity className="h-5 w-5" />
              </div>
              <h1 className="text-3xl font-semibold tracking-tight text-white">LAN Monitor</h1>
            </div>
            <p className="text-sm text-slate-400">A calm, live view of everything connected to your network.</p>
          </div>

          <div className="flex items-center gap-3">
            <div className={cn(
              "flex items-center gap-2 rounded-full border px-3 py-2 text-xs font-medium",
              isConnected
                ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                : "border-red-500/20 bg-red-500/10 text-red-400",
            )}>
              <span className={cn("h-2 w-2 rounded-full", isConnected ? "bg-emerald-400 status-online" : "bg-red-400")} />
              {isConnected ? "Live updates" : "Offline mode"}
            </div>
            <button
              onClick={handleScan}
              disabled={scanning}
              className={cn(
                "flex items-center gap-2 rounded-lg bg-brand-500 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-brand-600",
                "disabled:cursor-not-allowed disabled:opacity-60",
              )}
            >
              <RefreshCw className={cn("h-4 w-4", scanning && "animate-spin")} />
              {scanning ? "Scanning" : "Scan now"}
            </button>
          </div>
        </header>

        {(scanError || actionError) && (
          <div className="mb-5 flex items-center gap-3 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {scanError || actionError}
            <button onClick={() => { setScanError(null); setActionError(null); }} className="ml-auto text-xs text-red-200 underline">Dismiss</button>
          </div>
        )}

        <section className="glass mb-6 flex flex-wrap items-center gap-y-4 rounded-2xl px-4 py-4 md:px-6">
          <SummaryMetric label="Total devices" value={stats?.total_devices ?? 0} tone="bg-brand-400" />
          <SummaryMetric label="Online now" value={stats?.online_devices ?? 0} tone="bg-emerald-400" />
          <SummaryMetric label="Need review" value={stats?.new_devices ?? 0} tone="bg-amber-400" />
          <SummaryMetric label="Active in 24h" value={stats?.active_last_24h ?? 0} tone="bg-violet-400" />
          <div className="ml-auto hidden items-center gap-2 border-l border-slate-700/60 pl-5 text-xs text-slate-500 md:flex">
            <Clock className="h-3.5 w-3.5" />
            {stats?.last_scan_time ? `Last scan ${timeAgo(stats.last_scan_time)}` : "No scans yet"}
          </div>
        </section>

        <section className="glass overflow-hidden rounded-2xl">
          <div className="flex flex-col gap-4 border-b border-slate-700/60 p-4 md:flex-row md:items-center md:justify-between md:p-5">
            <div>
              <h2 className="text-base font-semibold text-white">Network devices</h2>
              <p className="mt-1 text-xs text-slate-500">Use the checkboxes for quick actions, or select a row to inspect details.</p>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative sm:w-72">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  type="search"
                  placeholder="Search devices..."
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-surface-900/70 py-2 pl-9 pr-3 text-sm text-white outline-none transition-colors placeholder:text-slate-600 focus:border-brand-500"
                />
              </div>
              <div className="flex rounded-lg border border-slate-700 bg-surface-900/50 p-1">
                {([
                  ["all", "All"],
                  ["online", "Online"],
                  ["offline", "Offline"],
                  ["new", "Needs review"],
                  ["known", "Known"],
                ] as [Filter, string][]).map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => setFilter(key)}
                    className={cn(
                      "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                      filter === key ? "bg-slate-700 text-white" : "text-slate-500 hover:text-slate-300",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {selectedDeviceIds.size > 0 && (
            <div className="flex flex-col gap-3 border-b border-brand-500/20 bg-brand-500/[0.06] px-4 py-3 sm:flex-row sm:items-center sm:justify-between md:px-5">
              <div className="flex items-center gap-3">
                <span className="text-sm font-medium text-white">
                  {selectedDeviceIds.size} selected
                </span>
                <button
                  onClick={() => setSelectedDeviceIds(new Set())}
                  className="text-xs text-slate-400 transition-colors hover:text-white"
                >
                  Clear selection
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => void handleBulkQuickAction("favorite")}
                  disabled={bulkActionLoading !== null}
                  className="flex items-center gap-2 rounded-md border border-slate-700 bg-surface-900/60 px-3 py-2 text-xs font-medium text-slate-300 transition-colors hover:border-amber-400/40 hover:bg-amber-400/10 hover:text-amber-300 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Star className={cn("h-3.5 w-3.5", allSelectedAreFavorites && "fill-amber-400 text-amber-400")} />
                  {allSelectedAreFavorites ? "Unstar selected" : "Star selected"}
                </button>
                <button
                  onClick={() => void handleBulkQuickAction("known")}
                  disabled={bulkActionLoading !== null}
                  className="flex items-center gap-2 rounded-md border border-slate-700 bg-surface-900/60 px-3 py-2 text-xs font-medium text-slate-300 transition-colors hover:border-emerald-400/40 hover:bg-emerald-400/10 hover:text-emerald-300 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Check className="h-3.5 w-3.5" />
                  Mark known
                </button>
                <button
                  onClick={() => void handleBulkDelete()}
                  disabled={bulkActionLoading !== null}
                  className="flex items-center gap-2 rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Delete selected
                </button>
              </div>
            </div>
          )}

          {scanning && (
            <div className="flex items-center gap-3 border-b border-brand-500/20 bg-brand-500/5 px-5 py-3 text-xs text-brand-200">
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-brand-400" />
              Scanning in the background. You can still open devices and save changes.
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-24 text-slate-500">
              <RefreshCw className="mr-3 h-5 w-5 animate-spin text-brand-400" /> Loading devices...
            </div>
          ) : filteredDevices.length === 0 ? (
            <div className="flex flex-col items-center justify-center px-5 py-24 text-center">
              <HelpCircle className="mb-3 h-10 w-10 text-slate-600" />
              <p className="text-sm text-slate-400">No devices match this view.</p>
              {(search || filter !== "all") && (
                <button onClick={() => { setSearch(""); setFilter("all"); }} className="mt-2 text-xs text-brand-400 hover:underline">Clear filters</button>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[920px] table-fixed text-left">
                <colgroup>
                  <col className="w-[4%]" />
                  <col className="w-[26%]" />
                  <col className="w-[14%]" />
                  <col className="w-[12%]" />
                  <col className="w-[18%]" />
                  <col className="w-[12%]" />
                  <col className="w-[14%]" />
                </colgroup>
                <thead className="border-b border-slate-700/60 bg-surface-900/30 text-[11px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="px-3 py-3 text-center font-medium">
                      <input
                        ref={selectAllRef}
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={toggleVisibleSelection}
                        disabled={bulkActionLoading !== null}
                        aria-label="Select all visible devices"
                        className="h-4 w-4 cursor-pointer rounded border-slate-600 bg-slate-800 accent-brand-500 focus:ring-2 focus:ring-brand-500/40 disabled:cursor-not-allowed"
                      />
                    </th>
                    <SortableHeader label="Device" sortKey="device" sortConfig={sortConfig} onSort={handleSort} />
                    <SortableHeader label="IP address" sortKey="ip" sortConfig={sortConfig} onSort={handleSort} />
                    <SortableHeader label="Status" sortKey="status" sortConfig={sortConfig} onSort={handleSort} />
                    <SortableHeader label="Vendor / type" sortKey="vendor" sortConfig={sortConfig} onSort={handleSort} />
                    <SortableHeader label="Last seen" sortKey="lastSeen" sortConfig={sortConfig} onSort={handleSort} />
                    <th className="px-3 py-3 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {filteredDevices.map((device) => {
                    const Icon = iconMap[getDeviceIcon(device)] || HelpCircle;
                    const isSelected = selectedDevice?.id === device.id;
                    const isBulkSelected = selectedDeviceIds.has(device.id);
                    const aliases = parseMacAliases(device);
                    const services = parseStringArray(device.services);
                    const macRotationDetected = device.mac_rotation_detected ?? aliases.length > 0;
                    return (
                      <tr
                        key={device.id}
                        tabIndex={0}
                        onClick={() => setSelectedDevice(device)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") setSelectedDevice(device);
                        }}
                        className={cn(
                          "group cursor-pointer outline-none transition-colors hover:bg-slate-800/45 focus:bg-slate-800/45",
                          (isSelected || isBulkSelected) && "bg-brand-500/[0.08]",
                        )}
                      >
                        <td className="px-3 py-3.5 text-center">
                          <input
                            type="checkbox"
                            checked={isBulkSelected}
                            onChange={() => toggleDeviceSelection(device.id)}
                            onClick={(event) => event.stopPropagation()}
                            disabled={bulkActionLoading !== null}
                            aria-label={`Select ${deviceName(device)}`}
                            className="h-4 w-4 cursor-pointer rounded border-slate-600 bg-slate-800 accent-brand-500 focus:ring-2 focus:ring-brand-500/40 disabled:cursor-not-allowed"
                          />
                        </td>
                        <td className="px-3 py-3.5">
                          <div className="flex min-w-0 items-center gap-3">
                            <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg", device.is_online ? "bg-brand-500/15 text-brand-300" : "bg-slate-800 text-slate-500")}>
                              <Icon className="h-4 w-4" />
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <p className="truncate text-sm font-medium text-white">{deviceName(device)}</p>
                                {device.is_favorite && <Star className="h-3.5 w-3.5 shrink-0 fill-amber-400 text-amber-400" />}
                                {!device.is_known && <span className="rounded-full bg-amber-400/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">Review</span>}
                                {macRotationDetected && <span className="rounded-full bg-sky-400/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-300">Rotating MAC</span>}
                                {!macRotationDetected && device.is_private_mac && <span className="rounded-full bg-violet-400/10 px-1.5 py-0.5 text-[10px] font-medium text-violet-300">Private MAC</span>}
                              </div>
                              <p className="mt-0.5 truncate font-mono text-[11px] text-slate-600">{formatMacAddress(device.mac_address)}{macRotationDetected && ` · ${aliases.length} previous MAC${aliases.length === 1 ? "" : "s"}`}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-3 py-3.5 font-mono text-xs text-slate-300">
                          <p>{device.ip_address || "—"}</p>
                          {device.hostname && device.hostname !== deviceName(device) && (
                            <p className="mt-1 truncate font-sans text-[11px] text-slate-600" title={device.hostname}>{device.hostname}</p>
                          )}
                        </td>
                        <td className="px-3 py-3.5">
                          <span className={cn("inline-flex items-center gap-1.5 text-xs", device.is_online ? "text-emerald-400" : "text-slate-500")}>
                            {device.is_online ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
                            {device.is_online ? "Online" : "Offline"}
                          </span>
                        </td>
                        <td className="px-3 py-3.5">
                          <p className="truncate text-xs text-slate-300">{device.manufacturer || device.vendor || "Unknown vendor"}</p>
                          <p className="mt-0.5 truncate text-[11px] text-slate-600">{device.effective_device_type || device.model || "Unclassified"}</p>
                        </td>
                        <td className="px-3 py-3.5 text-xs text-slate-500">{timeAgo(device.last_seen)}</td>
                        <td className="px-3 py-3.5">
                          <div className="flex items-center justify-end gap-1">
                            <button
                              title={device.is_favorite ? "Remove star" : "Star device"}
                              aria-label={device.is_favorite ? "Remove star" : "Star device"}
                              disabled={bulkActionLoading !== null || actionLoading === `favorite-${device.id}`}
                              onClick={(event) => { event.stopPropagation(); void handleQuickAction(device, "favorite"); }}
                              className={cn("rounded-md p-2 transition-colors disabled:opacity-50", device.is_favorite ? "text-amber-400 hover:bg-amber-400/10" : "text-slate-600 hover:bg-slate-700 hover:text-slate-300")}
                            >
                              <Star className={cn("h-4 w-4", device.is_favorite && "fill-amber-400")} />
                            </button>
                            {!device.is_known && (
                              <button
                                title="Mark as known"
                                aria-label="Mark as known"
                                disabled={bulkActionLoading !== null || actionLoading === `known-${device.id}`}
                                onClick={(event) => { event.stopPropagation(); void handleQuickAction(device, "known"); }}
                                className="rounded-md p-2 text-slate-600 transition-colors hover:bg-emerald-500/10 hover:text-emerald-400 disabled:opacity-50"
                              >
                                <Check className="h-4 w-4" />
                              </button>
                            )}
                            <button
                              title="Delete device"
                              aria-label={`Delete ${deviceName(device)}`}
                              disabled={bulkActionLoading !== null || actionLoading === `delete-${device.id}`}
                              onClick={(event) => { event.stopPropagation(); void handleDeleteQuickAction(device); }}
                              className="rounded-md p-2 text-slate-600 transition-colors hover:bg-red-500/10 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                            <button
                              title="Open details"
                              aria-label={`Open details for ${deviceName(device)}`}
                              onClick={(event) => { event.stopPropagation(); setSelectedDevice(device); }}
                              className="rounded-md p-2 text-slate-600 transition-colors hover:bg-slate-700 hover:text-slate-300"
                            >
                              <ChevronRight className="h-4 w-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <footer className="mt-5 flex items-center justify-between px-1 text-xs text-slate-600">
          <span>{filteredDevices.length} of {devices.length} devices shown</span>
          <span className="hidden items-center gap-1 md:flex"><MoreHorizontal className="h-3.5 w-3.5" /> Details are one click away</span>
        </footer>
      </div>

      <AnimatePresence>
        {selectedDevice && (
          <DeviceModal
            device={selectedDevice}
            onClose={() => setSelectedDevice(null)}
            onUpdate={updateDeviceInState}
            onDelete={(deviceId) => {
              setDevices((current) => current.filter((device) => device.id !== deviceId));
              setSelectedDeviceIds((current) => {
                const next = new Set(current);
                next.delete(deviceId);
                return next;
              });
              setSelectedDevice(null);
              void fetchData();
            }}
          />
        )}
      </AnimatePresence>
    </main>
  );
}
