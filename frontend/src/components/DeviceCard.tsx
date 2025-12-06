"use client";

import { motion } from "framer-motion";
import { 
  Wifi, 
  WifiOff, 
  Star,
  Clock,
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
  Network,
} from "lucide-react";
import { Device } from "@/types";
import { cn, formatMacAddress, getDeviceIcon, timeAgo } from "@/lib/utils";

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

// Common port to service name mapping
const portNames: Record<number, string> = {
  22: "SSH",
  23: "Telnet",
  53: "DNS",
  80: "HTTP",
  443: "HTTPS",
  445: "SMB",
  548: "AFP",
  631: "IPP",
  3389: "RDP",
  5000: "UPnP",
  5001: "Synology",
  7000: "AirTunes",
  8080: "HTTP",
  8443: "HTTPS",
  9100: "Print",
  32400: "Plex",
  62078: "iOS",
};

function parseOpenPorts(openPorts: string | null): number[] {
  if (!openPorts) return [];
  try {
    const parsed = JSON.parse(openPorts);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function getPortLabel(port: number): string {
  return portNames[port] || port.toString();
}

interface DeviceCardProps {
  device: Device;
  onClick: () => void;
  index: number;
}

export default function DeviceCard({ device, onClick, index }: DeviceCardProps) {
  const iconKey = getDeviceIcon(device);
  const Icon = iconMap[iconKey] || HelpCircle;
  
  const displayName = device.custom_name || device.hostname || formatMacAddress(device.mac_address);
  const openPorts = parseOpenPorts(device.open_ports);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ duration: 0.3, delay: index * 0.02 }}
      onClick={onClick}
      className={cn(
        "glass rounded-xl p-4 cursor-pointer card-hover relative overflow-hidden group",
        !device.is_known && "border-yellow-500/50"
      )}
    >
      {/* Status indicator bar */}
      <div className={cn(
        "absolute top-0 left-0 right-0 h-1",
        device.is_online ? "bg-gradient-to-r from-emerald-500 to-emerald-400" : "bg-slate-600"
      )} />
      
      {/* Favorite star */}
      {device.is_favorite && (
        <Star className="absolute top-3 right-3 w-4 h-4 text-yellow-400 fill-yellow-400" />
      )}
      
      {/* New device badge */}
      {!device.is_known && !device.is_favorite && (
        <span className="absolute top-3 right-3 px-2 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded-full">
          New
        </span>
      )}
      
      <div className="flex items-start gap-4 mt-2">
        {/* Device icon */}
        <div className={cn(
          "w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0",
          device.is_online 
            ? "bg-brand-500/20 text-brand-400" 
            : "bg-slate-700/50 text-slate-400"
        )}>
          <Icon className="w-6 h-6" />
        </div>
        
        {/* Device info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-white truncate">
              {displayName}
            </h3>
            {device.is_online ? (
              <Wifi className="w-4 h-4 text-emerald-500 flex-shrink-0" />
            ) : (
              <WifiOff className="w-4 h-4 text-slate-500 flex-shrink-0" />
            )}
          </div>
          
          <div className="flex items-center gap-2">
            {device.ip_address && (
              <p className="text-sm text-slate-400 font-mono">
                {device.ip_address}
              </p>
            )}
            {device.device_type && (
              <span className="text-xs px-1.5 py-0.5 bg-brand-500/20 text-brand-300 rounded">
                {device.device_type}
              </span>
            )}
          </div>
          
          {device.vendor && (
            <p className="text-xs text-slate-500 truncate mt-1">
              {device.vendor}
            </p>
          )}
        </div>
      </div>
      
      {/* Open Ports */}
      {openPorts.length > 0 && (
        <div className="mt-3 flex items-center gap-2 flex-wrap">
          <Network className="w-3 h-3 text-slate-500" />
          <div className="flex gap-1 flex-wrap">
            {openPorts.slice(0, 6).map((port) => (
              <span
                key={port}
                className="text-[10px] px-1.5 py-0.5 bg-slate-700/80 text-slate-300 rounded font-mono"
                title={`Port ${port}`}
              >
                {getPortLabel(port)}
              </span>
            ))}
            {openPorts.length > 6 && (
              <span className="text-[10px] px-1.5 py-0.5 bg-slate-700/80 text-slate-400 rounded">
                +{openPorts.length - 6}
              </span>
            )}
          </div>
        </div>
      )}
      
      {/* Footer */}
      <div className="flex items-center justify-between mt-4 pt-3 border-t border-slate-700/50">
        <span className="text-xs font-mono text-slate-500">
          {formatMacAddress(device.mac_address)}
        </span>
        <span className="text-xs text-slate-500 flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {timeAgo(device.last_seen)}
        </span>
      </div>
      
      {/* Hover glow effect */}
      <div className={cn(
        "absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none",
        "bg-gradient-to-r from-brand-500/5 to-purple-500/5 rounded-xl"
      )} />
    </motion.div>
  );
}
