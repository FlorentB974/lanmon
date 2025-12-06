"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Activity, 
  Wifi, 
  WifiOff, 
  RefreshCw, 
  Search,
  Monitor,
  Smartphone,
  Laptop,
  Tv,
  Router,
  Speaker,
  Cpu,
  Printer,
  Camera,
  Tablet,
  HelpCircle,
  Star,
  AlertCircle,
  Clock,
  TrendingUp,
  Zap
} from "lucide-react";
import { api } from "@/lib/api";
import { useWebSocket } from "@/lib/useWebSocket";
import { Device, DashboardStats } from "@/types";
import { cn, formatMacAddress, getDeviceIcon, timeAgo } from "@/lib/utils";
import DeviceCard from "@/components/DeviceCard";
import StatsCard from "@/components/StatsCard";
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

export default function Home() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "online" | "offline" | "new">("all");
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const { isConnected, lastMessage } = useWebSocket();

  const fetchData = useCallback(async () => {
    try {
      const [devicesRes, statsRes] = await Promise.all([
        api.getDevices({ limit: 500 }),
        api.getDashboardStats(),
      ]);
      setDevices(devicesRes.devices);
      setStats(statsRes);
    } catch (error) {
      console.error("Failed to fetch data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Handle WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      const { type, data } = lastMessage;
      
      if (type === "scan_completed" || type === "device_new" || type === "device_connected" || type === "device_disconnected") {
        fetchData();
      }
      
      if (type === "scan_started") {
        setScanning(true);
      }
      
      if (type === "scan_completed" || type === "scan_failed") {
        setScanning(false);
      }
    }
  }, [lastMessage, fetchData]);

  const handleScan = async () => {
    setScanning(true);
    try {
      await api.triggerScan();
      await fetchData();
    } catch (error) {
      console.error("Scan failed:", error);
    } finally {
      setScanning(false);
    }
  };

  const filteredDevices = devices.filter((device) => {
    // Apply search filter
    const searchLower = search.toLowerCase();
    const matchesSearch =
      !search ||
      device.hostname?.toLowerCase().includes(searchLower) ||
      device.custom_name?.toLowerCase().includes(searchLower) ||
      device.ip_address?.toLowerCase().includes(searchLower) ||
      device.mac_address.toLowerCase().includes(searchLower) ||
      device.vendor?.toLowerCase().includes(searchLower);

    // Apply status filter
    let matchesFilter = true;
    if (filter === "online") matchesFilter = device.is_online;
    if (filter === "offline") matchesFilter = !device.is_online;
    if (filter === "new") matchesFilter = !device.is_known;

    return matchesSearch && matchesFilter;
  });

  return (
    <main className="min-h-screen p-4 md:p-8">
      {/* Header */}
      <header className="mb-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl md:text-4xl font-bold gradient-text flex items-center gap-3">
              <Activity className="w-8 h-8 md:w-10 md:h-10 text-brand-500" />
              LAN Monitor
            </h1>
            <p className="text-slate-400 mt-1">
              Real-time network device monitoring
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Connection status */}
            <div className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-full text-sm",
              isConnected ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"
            )}>
              <span className={cn(
                "w-2 h-2 rounded-full",
                isConnected ? "bg-emerald-500 status-online" : "bg-red-500"
              )} />
              {isConnected ? "Live" : "Disconnected"}
            </div>
            
            {/* Scan button */}
            <motion.button
              onClick={handleScan}
              disabled={scanning}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all",
                "bg-brand-500 hover:bg-brand-600 text-white",
                "disabled:opacity-50 disabled:cursor-not-allowed",
                scanning && "glow-brand"
              )}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <RefreshCw className={cn("w-4 h-4", scanning && "animate-spin")} />
              {scanning ? "Scanning..." : "Scan Now"}
            </motion.button>
          </div>
        </div>
      </header>

      {/* Stats Grid */}
      <section className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-8">
        <StatsCard
          icon={Monitor}
          label="Total Devices"
          value={stats?.total_devices ?? 0}
          color="blue"
        />
        <StatsCard
          icon={Wifi}
          label="Online"
          value={stats?.online_devices ?? 0}
          color="green"
        />
        <StatsCard
          icon={WifiOff}
          label="Offline"
          value={stats?.offline_devices ?? 0}
          color="gray"
        />
        <StatsCard
          icon={AlertCircle}
          label="New Devices"
          value={stats?.new_devices ?? 0}
          color="yellow"
        />
        <StatsCard
          icon={TrendingUp}
          label="Active 24h"
          value={stats?.active_last_24h ?? 0}
          color="purple"
        />
        <StatsCard
          icon={Zap}
          label="Events 24h"
          value={stats?.events_last_24h ?? 0}
          color="orange"
        />
      </section>

      {/* Search and Filters */}
      <section className="mb-6">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
            <input
              type="text"
              placeholder="Search by name, IP, MAC, or vendor..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-surface-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-all"
            />
          </div>
          
          {/* Filters */}
          <div className="flex gap-2">
            {[
              { key: "all", label: "All" },
              { key: "online", label: "Online" },
              { key: "offline", label: "Offline" },
              { key: "new", label: "New" },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setFilter(key as typeof filter)}
                className={cn(
                  "px-4 py-2 rounded-lg font-medium transition-all",
                  filter === key
                    ? "bg-brand-500 text-white"
                    : "bg-surface-800/50 text-slate-400 hover:text-white hover:bg-surface-700"
                )}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Devices Grid */}
      <section>
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <RefreshCw className="w-8 h-8 text-brand-500 animate-spin" />
          </div>
        ) : filteredDevices.length === 0 ? (
          <div className="text-center py-20">
            <HelpCircle className="w-12 h-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No devices found</p>
            {search && (
              <button
                onClick={() => setSearch("")}
                className="mt-2 text-brand-500 hover:underline"
              >
                Clear search
              </button>
            )}
          </div>
        ) : (
          <motion.div 
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3 }}
          >
            <AnimatePresence>
              {filteredDevices.map((device, index) => (
                <DeviceCard
                  key={device.id}
                  device={device}
                  onClick={() => setSelectedDevice(device)}
                  index={index}
                />
              ))}
            </AnimatePresence>
          </motion.div>
        )}
      </section>

      {/* Device Modal */}
      <AnimatePresence>
        {selectedDevice && (
          <DeviceModal
            device={selectedDevice}
            onClose={() => setSelectedDevice(null)}
            onUpdate={(updated) => {
              setDevices(devices.map(d => d.id === updated.id ? updated : d));
              setSelectedDevice(updated);
            }}
          />
        )}
      </AnimatePresence>

      {/* Last scan info */}
      {stats?.last_scan_time && (
        <footer className="mt-8 text-center text-sm text-slate-500">
          <Clock className="w-4 h-4 inline mr-1" />
          Last scan: {timeAgo(stats.last_scan_time)}
        </footer>
      )}
    </main>
  );
}
