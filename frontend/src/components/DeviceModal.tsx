"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { 
  X, 
  Wifi, 
  WifiOff, 
  Star, 
  Clock, 
  Calendar,
  Edit3,
  Save,
  Trash2,
  History,
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
  ChevronDown,
  ChevronUp,
  Network,
  Globe,
  Lock,
  Server,
} from "lucide-react";
import { Device, ScanEvent } from "@/types";
import { api } from "@/lib/api";
import { cn, formatMacAddress, getDeviceIcon, timeAgo } from "@/lib/utils";
import { format } from "date-fns";

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

// Port information database
const portInfo: Record<number, { name: string; description: string; icon: React.ComponentType<{ className?: string }> }> = {
  22: { name: "SSH", description: "Secure Shell", icon: Lock },
  23: { name: "Telnet", description: "Telnet Protocol", icon: Server },
  53: { name: "DNS", description: "Domain Name System", icon: Globe },
  80: { name: "HTTP", description: "Web Server", icon: Globe },
  443: { name: "HTTPS", description: "Secure Web Server", icon: Lock },
  445: { name: "SMB", description: "Windows File Sharing", icon: Server },
  548: { name: "AFP", description: "Apple File Protocol", icon: Server },
  631: { name: "IPP", description: "Internet Printing", icon: Printer },
  3389: { name: "RDP", description: "Remote Desktop", icon: Monitor },
  5000: { name: "UPnP", description: "Universal Plug and Play", icon: Network },
  5001: { name: "Synology", description: "Synology DSM", icon: Server },
  7000: { name: "AirTunes", description: "Apple AirPlay", icon: Speaker },
  8080: { name: "HTTP Alt", description: "Alternative HTTP", icon: Globe },
  8443: { name: "HTTPS Alt", description: "Alternative HTTPS", icon: Lock },
  9100: { name: "JetDirect", description: "Network Printing", icon: Printer },
  32400: { name: "Plex", description: "Plex Media Server", icon: Tv },
  49152: { name: "UPnP", description: "UPnP Dynamic", icon: Network },
  62078: { name: "iOS Sync", description: "iPhone/iPad Sync", icon: Smartphone },
};

function parseOpenPorts(openPorts: string | null): number[] {
  if (!openPorts) return [];
  try {
    const parsed = JSON.parse(openPorts);
    return Array.isArray(parsed) ? parsed.sort((a, b) => a - b) : [];
  } catch {
    return [];
  }
}

function getPortInfo(port: number) {
  return portInfo[port] || { name: port.toString(), description: "Unknown Service", icon: Network };
}

const deviceTypes = [
  { value: "", label: "Auto-detect" },
  { value: "router", label: "Router/Gateway" },
  { value: "computer", label: "Computer/Desktop" },
  { value: "laptop", label: "Laptop" },
  { value: "phone", label: "Phone" },
  { value: "tablet", label: "Tablet" },
  { value: "tv", label: "TV/Display" },
  { value: "printer", label: "Printer" },
  { value: "camera", label: "Camera" },
  { value: "speaker", label: "Speaker/Audio" },
  { value: "iot", label: "IoT/Smart Device" },
  { value: "other", label: "Other" },
];

interface DeviceModalProps {
  device: Device;
  onClose: () => void;
  onUpdate: (device: Device) => void;
}

export default function DeviceModal({ device, onClose, onUpdate }: DeviceModalProps) {
  const [isEditing, setIsEditing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(false);
  
  const [form, setForm] = useState({
    custom_name: device.custom_name || "",
    device_type: device.device_type || "",
    notes: device.notes || "",
    is_favorite: device.is_favorite,
    is_known: device.is_known,
  });

  const iconKey = getDeviceIcon(device);
  const Icon = iconMap[iconKey] || HelpCircle;

  useEffect(() => {
    if (showHistory) {
      loadEvents();
    }
  }, [showHistory]);

  const loadEvents = async () => {
    try {
      const data = await api.getDeviceEvents(device.id);
      setEvents(data);
    } catch (error) {
      console.error("Failed to load events:", error);
    }
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const updated = await api.updateDevice(device.id, form);
      onUpdate(updated);
      setIsEditing(false);
    } catch (error) {
      console.error("Failed to update device:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleFavorite = async () => {
    try {
      const updated = await api.updateDevice(device.id, {
        is_favorite: !device.is_favorite,
      });
      onUpdate(updated);
    } catch (error) {
      console.error("Failed to toggle favorite:", error);
    }
  };

  const handleMarkKnown = async () => {
    try {
      const updated = await api.updateDevice(device.id, { is_known: true });
      onUpdate(updated);
    } catch (error) {
      console.error("Failed to mark as known:", error);
    }
  };

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case "connected":
        return <Wifi className="w-4 h-4 text-emerald-500" />;
      case "disconnected":
        return <WifiOff className="w-4 h-4 text-red-500" />;
      case "ip_changed":
        return <Edit3 className="w-4 h-4 text-yellow-500" />;
      default:
        return <History className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="glass rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden"
      >
        {/* Header */}
        <div className="relative p-6 border-b border-slate-700/50">
          <div className={cn(
            "absolute top-0 left-0 right-0 h-1",
            device.is_online ? "bg-gradient-to-r from-emerald-500 to-emerald-400" : "bg-slate-600"
          )} />
          
          <button
            onClick={onClose}
            className="absolute top-4 right-4 p-2 rounded-lg hover:bg-slate-700/50 transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>

          <div className="flex items-start gap-4 mt-2">
            <div className={cn(
              "w-16 h-16 rounded-xl flex items-center justify-center",
              device.is_online 
                ? "bg-brand-500/20 text-brand-400" 
                : "bg-slate-700/50 text-slate-400"
            )}>
              <Icon className="w-8 h-8" />
            </div>
            
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-white">
                  {device.custom_name || device.friendly_name || device.hostname || formatMacAddress(device.mac_address)}
                </h2>
                {device.is_online ? (
                  <span className="flex items-center gap-1 px-2 py-0.5 bg-emerald-500/20 text-emerald-400 text-xs rounded-full">
                    <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full status-online" />
                    Online
                  </span>
                ) : (
                  <span className="flex items-center gap-1 px-2 py-0.5 bg-slate-500/20 text-slate-400 text-xs rounded-full">
                    <span className="w-1.5 h-1.5 bg-slate-500 rounded-full" />
                    Offline
                  </span>
                )}
              </div>
              
              <p className="text-slate-400 font-mono">
                {device.ip_address || "No IP"}
              </p>
              
              {(device.manufacturer || device.vendor) && (
                <p className="text-sm text-slate-500 mt-1">{device.manufacturer || device.vendor}</p>
              )}
            </div>

            <button
              onClick={handleToggleFavorite}
              className={cn(
                "p-2 rounded-lg transition-colors",
                device.is_favorite 
                  ? "text-yellow-400 hover:bg-yellow-400/20" 
                  : "text-slate-500 hover:bg-slate-700/50"
              )}
            >
              <Star className={cn("w-5 h-5", device.is_favorite && "fill-yellow-400")} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto max-h-[60vh]">
          {/* New device banner */}
          {!device.is_known && (
            <div className="mb-6 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex items-center justify-between">
              <div>
                <p className="font-medium text-yellow-400">New Device Detected</p>
                <p className="text-sm text-slate-400">This device was recently discovered on your network</p>
              </div>
              <button
                onClick={handleMarkKnown}
                className="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-black font-medium rounded-lg transition-colors"
              >
                Mark as Known
              </button>
            </div>
          )}

          {/* Device Info Grid */}
          <div className="grid grid-cols-2 gap-4 mb-6">
            <div className="p-3 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider">MAC Address</p>
              <p className="font-mono text-white mt-1">{formatMacAddress(device.mac_address)}</p>
            </div>
            <div className="p-3 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider">IP Address</p>
              <p className="font-mono text-white mt-1">{device.ip_address || "—"}</p>
            </div>
            {device.model && (
              <div className="p-3 bg-surface-800/50 rounded-lg">
                <p className="text-xs text-slate-500 uppercase tracking-wider">Model</p>
                <p className="text-white mt-1">{device.model}</p>
              </div>
            )}
            {device.manufacturer && (
              <div className="p-3 bg-surface-800/50 rounded-lg">
                <p className="text-xs text-slate-500 uppercase tracking-wider">Manufacturer</p>
                <p className="text-white mt-1">{device.manufacturer}</p>
              </div>
            )}
            {device.friendly_name && device.friendly_name !== device.hostname && (
              <div className="p-3 bg-surface-800/50 rounded-lg">
                <p className="text-xs text-slate-500 uppercase tracking-wider">Friendly Name</p>
                <p className="text-white mt-1">{device.friendly_name}</p>
              </div>
            )}
            <div className="p-3 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider flex items-center gap-1">
                <Calendar className="w-3 h-3" /> First Seen
              </p>
              <p className="text-white mt-1">{format(new Date(device.first_seen), "PPp")}</p>
            </div>
            <div className="p-3 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider flex items-center gap-1">
                <Clock className="w-3 h-3" /> Last Seen
              </p>
              <p className="text-white mt-1">{format(new Date(device.last_seen), "PPp")}</p>
            </div>
          </div>

          {/* Open Ports Section */}
          {(() => {
            const openPorts = parseOpenPorts(device.open_ports);
            if (openPorts.length === 0) return null;
            
            return (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Network className="w-4 h-4" />
                  Open Ports ({openPorts.length})
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {openPorts.map((port) => {
                    const info = getPortInfo(port);
                    const PortIcon = info.icon;
                    return (
                      <div
                        key={port}
                        className="p-2 bg-surface-800/50 rounded-lg flex items-center gap-2 group hover:bg-surface-700/50 transition-colors"
                      >
                        <div className="w-8 h-8 rounded-lg bg-brand-500/10 flex items-center justify-center text-brand-400">
                          <PortIcon className="w-4 h-4" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-white truncate">{info.name}</p>
                          <p className="text-xs text-slate-500 truncate">Port {port}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })()}

          {/* mDNS Services Section */}
          {(() => {
            if (!device.services) return null;
            
            let services: string[] = [];
            try {
              const parsed = JSON.parse(device.services);
              services = Array.isArray(parsed) ? parsed : [];
            } catch {
              services = [];
            }
            
            if (services.length === 0) return null;
            
            return (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Server className="w-4 h-4" />
                  Discovered Services ({services.length})
                </h3>
                <div className="space-y-2">
                  {services.slice(0, 10).map((service, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-surface-800/50 rounded-lg text-sm text-slate-300 font-mono text-xs"
                    >
                      {service}
                    </div>
                  ))}
                  {services.length > 10 && (
                    <p className="text-xs text-slate-500 text-center pt-2">
                      +{services.length - 10} more services
                    </p>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Edit Section */}
          {isEditing ? (
            <div className="space-y-4 mb-6">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Custom Name</label>
                <input
                  type="text"
                  value={form.custom_name}
                  onChange={(e) => setForm({ ...form, custom_name: e.target.value })}
                  placeholder="e.g., Living Room TV"
                  className="w-full px-4 py-2 bg-surface-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-brand-500"
                />
              </div>
              
              <div>
                <label className="block text-sm text-slate-400 mb-1">Device Type</label>
                <select
                  value={form.device_type}
                  onChange={(e) => setForm({ ...form, device_type: e.target.value })}
                  className="w-full px-4 py-2 bg-surface-800/50 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-brand-500"
                >
                  {deviceTypes.map(({ value, label }) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>
              
              <div>
                <label className="block text-sm text-slate-400 mb-1">Notes</label>
                <textarea
                  value={form.notes}
                  onChange={(e) => setForm({ ...form, notes: e.target.value })}
                  placeholder="Add notes about this device..."
                  rows={3}
                  className="w-full px-4 py-2 bg-surface-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 resize-none"
                />
              </div>
              
              <div className="flex gap-2">
                <button
                  onClick={handleSave}
                  disabled={loading}
                  className="flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  <Save className="w-4 h-4" />
                  Save Changes
                </button>
                <button
                  onClick={() => setIsEditing(false)}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={() => setIsEditing(true)}
              className="flex items-center gap-2 px-4 py-2 bg-surface-800/50 hover:bg-surface-700 text-slate-300 rounded-lg transition-colors mb-6"
            >
              <Edit3 className="w-4 h-4" />
              Edit Device
            </button>
          )}

          {/* Notes display */}
          {device.notes && !isEditing && (
            <div className="mb-6 p-4 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Notes</p>
              <p className="text-slate-300">{device.notes}</p>
            </div>
          )}

          {/* Connection History */}
          <div className="border-t border-slate-700/50 pt-6">
            <button
              onClick={() => setShowHistory(!showHistory)}
              className="flex items-center justify-between w-full text-left"
            >
              <h3 className="font-semibold text-white flex items-center gap-2">
                <History className="w-5 h-5 text-slate-400" />
                Connection History
              </h3>
              {showHistory ? (
                <ChevronUp className="w-5 h-5 text-slate-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>
            
            {showHistory && (
              <div className="mt-4 space-y-2">
                {events.length === 0 ? (
                  <p className="text-slate-500 text-sm">No events recorded</p>
                ) : (
                  events.slice(0, 10).map((event) => (
                    <div
                      key={event.id}
                      className="flex items-center gap-3 p-3 bg-surface-800/30 rounded-lg"
                    >
                      {getEventIcon(event.event_type)}
                      <div className="flex-1">
                        <p className="text-sm text-white capitalize">
                          {event.event_type.replace("_", " ")}
                        </p>
                        {event.event_type === "ip_changed" && event.old_ip_address && (
                          <p className="text-xs text-slate-500">
                            {event.old_ip_address} → {event.ip_address}
                          </p>
                        )}
                      </div>
                      <p className="text-xs text-slate-500">
                        {timeAgo(event.timestamp)}
                      </p>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
