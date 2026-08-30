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
  AlertCircle,
  CheckCircle2,
  RefreshCw,
  ScanSearch,
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

function parseMacAliases(macAliases: string | null): string[] {
  if (!macAliases) return [];
  try {
    const parsed = JSON.parse(macAliases);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

interface DiscoveryInfo {
  hostnames?: string[];
  friendly_name?: string | null;
  mdns_services?: string[];
  network_services?: string[];
  netbios_name?: string | null;
  ssdp?: Record<string, unknown>;
  upnp?: Record<string, unknown>;
  http?: Record<string, unknown>;
  banners?: Record<string, string>;
  tls?: Record<string, unknown>;
  dhcp?: Record<string, unknown>;
  probes?: Record<string, string>;
}

function parseDiscoveryInfo(discoveryInfo: string | null): DiscoveryInfo {
  if (!discoveryInfo) return {};
  try {
    const parsed = JSON.parse(discoveryInfo);
    return parsed && typeof parsed === "object" ? parsed as DiscoveryInfo : {};
  } catch {
    return {};
  }
}

function parseServices(servicesValue: string | null, discoveryInfo: DiscoveryInfo): string[] {
  const values = [
    ...(() => {
      if (!servicesValue) return [];
      try {
        const parsed = JSON.parse(servicesValue);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    })(),
    ...(discoveryInfo.mdns_services || []),
    ...(discoveryInfo.network_services || []),
  ];
  return values.filter((value, index): value is string => typeof value === "string" && values.indexOf(value) === index);
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
  { value: "nas", label: "NAS/Storage" },
  { value: "server", label: "Server" },
  { value: "iot", label: "IoT/Smart Device" },
  { value: "other", label: "Other" },
];

interface DeviceModalProps {
  device: Device;
  onClose: () => void;
  onUpdate: (device: Device) => void;
  onDelete?: (deviceId: number) => void;
}

export default function DeviceModal({ device, onClose, onUpdate, onDelete }: DeviceModalProps) {
  const [isEditing, setIsEditing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [identifying, setIdentifying] = useState(false);
  const [acceptingSuggestion, setAcceptingSuggestion] = useState(false);
  const [actionLoading, setActionLoading] = useState<"favorite" | "known" | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const [form, setForm] = useState({
    custom_name: device.custom_name || "",
    device_type: device.device_type || "",
    notes: device.notes || "",
    is_favorite: device.is_favorite,
    is_known: device.is_known,
  });

  const iconKey = getDeviceIcon(device);
  const Icon = iconMap[iconKey] || HelpCircle;
  const macAliases = parseMacAliases(device.mac_aliases);
  const discoveryInfo = parseDiscoveryInfo(device.discovery_info);
  const discoveredServices = parseServices(device.services, discoveryInfo);

  useEffect(() => {
    setForm({
      custom_name: device.custom_name || "",
      device_type: device.device_type || "",
      notes: device.notes || "",
      is_favorite: device.is_favorite,
      is_known: device.is_known,
    });
    setIsEditing(false);
    setError(null);
  }, [device.id]);

  useEffect(() => {
    if (showHistory) {
      loadEvents();
    }
  }, [showHistory]);

  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [onClose]);

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
    setError(null);
    try {
      const updated = await api.updateDevice(device.id, form);
      onUpdate(updated);
      setIsEditing(false);
    } catch (error) {
      console.error("Failed to update device:", error);
      setError("Could not save these changes. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleToggleFavorite = async () => {
    setActionLoading("favorite");
    setError(null);
    try {
      const updated = await api.updateDevice(device.id, {
        is_favorite: !device.is_favorite,
      });
      setForm((current) => ({ ...current, is_favorite: updated.is_favorite }));
      onUpdate(updated);
    } catch (error) {
      console.error("Failed to toggle favorite:", error);
      setError("Could not update the star. Please try again.");
    } finally {
      setActionLoading(null);
    }
  };

  const handleMarkKnown = async () => {
    setActionLoading("known");
    setError(null);
    try {
      const updated = await api.updateDevice(device.id, { is_known: true });
      setForm((current) => ({ ...current, is_known: updated.is_known }));
      onUpdate(updated);
    } catch (error) {
      console.error("Failed to mark as known:", error);
      setError("Could not mark this device as known. Please try again.");
    } finally {
      setActionLoading(null);
    }
  };

  const handleIdentify = async () => {
    setIdentifying(true);
    setError(null);
    try {
      const updated = await api.identifyDevice(device.id);
      onUpdate(updated);
    } catch (error) {
      console.error("Failed to identify device:", error);
      setError(error instanceof Error ? error.message : "Could not identify this device.");
    } finally {
      setIdentifying(false);
    }
  };

  const handleAcceptSuggestion = async () => {
    const category = device.identification?.category;
    if (!category) return;
    setAcceptingSuggestion(true);
    setError(null);
    try {
      const updated = await api.updateDevice(device.id, { device_type: category });
      setForm((current) => ({ ...current, device_type: category }));
      onUpdate(updated);
    } catch (error) {
      console.error("Failed to accept suggestion:", error);
      setError(error instanceof Error ? error.message : "Could not accept this suggestion.");
    } finally {
      setAcceptingSuggestion(false);
    }
  };

  const handleDelete = async () => {
    setLoading(true);
    setError(null);
    try {
      await api.deleteDevice(device.id);
      if (onDelete) {
        onDelete(device.id);
      }
      onClose();
    } catch (error) {
      console.error("Failed to delete device:", error);
      setError("Could not delete this device. Please try again.");
    } finally {
      setLoading(false);
      setShowDeleteConfirm(false);
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
      role="presentation"
      className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Device details"
        className="glass ml-auto flex h-full w-full max-w-xl flex-col overflow-hidden rounded-l-2xl border-y-0 border-r-0"
      >
        {/* Header */}
        <div className="relative shrink-0 border-b border-slate-700/50 p-6">
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
              disabled={actionLoading === "favorite"}
              aria-label={device.is_favorite ? "Remove star" : "Star device"}
              className={cn(
                "rounded-lg p-2 transition-colors disabled:opacity-50",
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
        <div className="flex-1 overflow-y-auto p-6">
          {error && (
            <div className="mb-5 flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {(device.mac_rotation_detected || device.is_private_mac) && (
            <div className={cn(
              "mb-5 rounded-lg border p-3 text-sm",
              device.mac_rotation_detected
                ? "border-sky-500/30 bg-sky-500/10 text-sky-200"
                : "border-violet-500/30 bg-violet-500/10 text-violet-200",
            )}>
              <p className="font-medium">
                {device.mac_rotation_detected ? "MAC rotation detected" : "Private MAC address"}
              </p>
              <p className="mt-1 text-xs text-slate-400">
                {device.mac_rotation_detected
                  ? "This device has been kept together across more than one Wi-Fi MAC address."
                  : "This address is locally administered; it may be a device privacy address."}
              </p>
            </div>
          )}

          {/* User acknowledgement is separate from scanner confidence. */}
          {!device.is_known && (
            <div className="mb-6 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex items-center justify-between">
              <div>
                <p className="font-medium text-yellow-400">Device needs review</p>
                <p className="text-sm text-slate-400">Acknowledge it after deciding whether it belongs on your network.</p>
              </div>
              <button
                onClick={handleMarkKnown}
                disabled={actionLoading === "known"}
                className="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-black font-medium rounded-lg transition-colors"
              >
                Mark as Known
              </button>
            </div>
          )}

          {/* Evidence-based scanner suggestion, kept separate from user type. */}
          <div className="mb-6 rounded-xl border border-brand-500/20 bg-brand-500/[0.06] p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <ScanSearch className="h-4 w-4 text-brand-400" />
                  <p className="text-sm font-semibold text-white">Scanner identification</p>
                </div>
                {device.identification?.label ? (
                  <div className="mt-2">
                    <p className="text-base text-brand-100">
                      Likely {device.identification.label}
                      {device.identification.confidence && (
                        <span className={cn(
                          "ml-2 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                          device.identification.confidence === "high"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : device.identification.confidence === "medium"
                              ? "bg-amber-500/15 text-amber-300"
                              : "bg-slate-500/20 text-slate-300",
                        )}>
                          {device.identification.confidence} confidence
                        </span>
                      )}
                    </p>
                    {device.device_type && (
                      <p className="mt-1 text-xs text-slate-500">Your type remains “{device.device_type}”. Scanner results never overwrite it.</p>
                    )}
                  </div>
                ) : (
                  <p className="mt-2 text-sm text-slate-400">
                    {device.identification?.ambiguous
                      ? "The available signals disagree, so no type was suggested."
                      : "There is not enough evidence for a reliable suggestion yet."}
                  </p>
                )}
              </div>
              <div className="flex shrink-0 gap-2">
                {device.identification?.category && device.device_type !== device.identification.category && (
                  <button
                    onClick={() => void handleAcceptSuggestion()}
                    disabled={acceptingSuggestion || identifying}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-500/20 disabled:opacity-50"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    {acceptingSuggestion ? "Accepting" : "Accept"}
                  </button>
                )}
                <button
                  onClick={() => void handleIdentify()}
                  disabled={identifying || !device.is_online}
                  title={!device.is_online ? "The device must be online" : "Run broader bounded probes"}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-brand-500 px-3 py-2 text-xs font-medium text-white transition-colors hover:bg-brand-600 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <RefreshCw className={cn("h-3.5 w-3.5", identifying && "animate-spin")} />
                  {identifying ? "Identifying" : "Identify"}
                </button>
              </div>
            </div>

            {device.identification?.evidence && device.identification.evidence.length > 0 && (
              <div className="mt-4 space-y-2 border-t border-brand-500/15 pt-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Evidence</p>
                {device.identification.evidence.map((item, index) => (
                  <div key={`${item.source}-${item.value}-${index}`} className="flex items-start gap-2 text-xs">
                    <span className={cn(
                      "mt-0.5 rounded px-1.5 py-0.5 font-medium uppercase",
                      item.strength === "strong" ? "bg-emerald-500/10 text-emerald-300" :
                        item.strength === "medium" ? "bg-amber-500/10 text-amber-300" : "bg-slate-700 text-slate-400",
                    )}>{item.source}</span>
                    <span className="text-slate-400">{item.summary}: <span className="font-mono text-slate-300">{item.value}</span></span>
                  </div>
                ))}
              </div>
            )}

            {device.identification?.probes && Object.keys(device.identification.probes).length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5 border-t border-brand-500/15 pt-3">
                {Object.entries(device.identification.probes).map(([source, status]) => (
                  <span key={source} className="rounded bg-surface-900/60 px-2 py-1 text-[10px] text-slate-500">
                    {source}: {status.replaceAll("_", " ")}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Device Info Grid */}
          <div className="grid grid-cols-2 gap-4 mb-6">
            <div className="p-3 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider">MAC Address</p>
              <p className="font-mono text-white mt-1">{formatMacAddress(device.mac_address)}</p>
            </div>
            {macAliases.length > 0 && (
              <div className="p-3 bg-surface-800/50 rounded-lg">
                <p className="text-xs text-slate-500 uppercase tracking-wider">Previous MACs</p>
                <p className="mt-1 font-mono text-xs text-slate-300">
                  {macAliases.map((mac) => formatMacAddress(mac)).join(", ")}
                </p>
                <p className="mt-1 text-[11px] text-slate-500">Private addresses grouped with this device</p>
              </div>
            )}
            <div className="p-3 bg-surface-800/50 rounded-lg">
              <p className="text-xs text-slate-500 uppercase tracking-wider">IP Address</p>
              <p className="font-mono text-white mt-1">{device.ip_address || "—"}</p>
            </div>
            {device.hostname && (
              <div className="p-3 bg-surface-800/50 rounded-lg">
                <p className="text-xs text-slate-500 uppercase tracking-wider">Hostname</p>
                <p className="text-white mt-1 break-words">{device.hostname}</p>
              </div>
            )}
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

          {/* Hostnames and protocol discovery */}
          {(discoveryInfo.hostnames?.length || discoveryInfo.netbios_name) && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Globe className="w-4 h-4" />
                Discovered Hostnames
              </h3>
              <div className="flex flex-wrap gap-2">
                {[...(discoveryInfo.hostnames || []), ...(discoveryInfo.netbios_name ? [discoveryInfo.netbios_name] : [])]
                  .filter((hostname, index, values) => hostname && values.indexOf(hostname) === index)
                  .map((hostname) => (
                    <span key={hostname} className="rounded-lg bg-surface-800/50 px-3 py-2 font-mono text-xs text-slate-300">
                      {hostname}
                    </span>
                  ))}
              </div>
            </div>
          )}

          {discoveredServices.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Server className="w-4 h-4" />
                Discovered Services ({discoveredServices.length})
              </h3>
              <div className="space-y-2">
                {discoveredServices.map((service, idx) => (
                  <div key={`${service}-${idx}`} className="p-2 bg-surface-800/50 rounded-lg text-xs text-slate-300 font-mono break-words">
                    {service}
                  </div>
                ))}
              </div>
            </div>
          )}

          {(["ssdp", "upnp", "http"] as const).map((section) => {
            const values = discoveryInfo[section];
            if (!values || Object.keys(values).length === 0) return null;
            const title = section === "ssdp" ? "SSDP Response" : section === "upnp" ? "UPnP Details" : "HTTP Details";
            return (
              <div key={section} className="mb-6">
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Network className="w-4 h-4" />
                  {title}
                </h3>
                <div className="space-y-2">
                  {Object.entries(values).map(([key, value]) => (
                    <div key={key} className="grid grid-cols-[minmax(90px,0.35fr)_1fr] gap-3 rounded-lg bg-surface-800/50 p-2 text-xs">
                      <span className="text-slate-500">{key}</span>
                      <span className="break-words font-mono text-slate-300">{String(value)}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}

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
            <div className="flex gap-2 mb-6">
              <button
                onClick={() => setIsEditing(true)}
                className="flex items-center gap-2 px-4 py-2 bg-surface-800/50 hover:bg-surface-700 text-slate-300 rounded-lg transition-colors"
              >
                <Edit3 className="w-4 h-4" />
                Edit Device
              </button>
              <button
                onClick={() => setShowDeleteConfirm(true)}
                className="flex items-center gap-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg transition-colors"
              >
                <Trash2 className="w-4 h-4" />
                Delete Device
              </button>
            </div>
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

        {/* Delete Confirmation Dialog */}
        {showDeleteConfirm && (
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-6 rounded-2xl">
            <div className="bg-surface-900 border border-red-500/30 rounded-xl p-6 max-w-md">
              <div className="flex items-start gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center flex-shrink-0">
                  <AlertCircle className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white mb-1">Delete Device?</h3>
                  <p className="text-sm text-slate-400">
                    Are you sure you want to delete <strong className="text-white">{device.custom_name || device.hostname || formatMacAddress(device.mac_address)}</strong>? This will remove all device data and history.
                  </p>
                </div>
              </div>
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setShowDeleteConfirm(false)}
                  disabled={loading}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDelete}
                  disabled={loading}
                  className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  <Trash2 className="w-4 h-4" />
                  {loading ? "Deleting..." : "Delete"}
                </button>
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}
