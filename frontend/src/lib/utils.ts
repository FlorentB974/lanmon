import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatMacAddress(mac: string): string {
  return mac.toUpperCase();
}

export function getDeviceIcon(device: {
  device_type?: string | null;
  vendor?: string | null;
  hostname?: string | null;
}): string {
  const type = device.device_type?.toLowerCase() || "";
  const vendor = device.vendor?.toLowerCase() || "";
  const hostname = device.hostname?.toLowerCase() || "";

  // Check device type first
  if (type.includes("router") || type.includes("gateway")) return "router";
  if (type.includes("phone") || type.includes("mobile")) return "smartphone";
  if (type.includes("tablet")) return "tablet";
  if (type.includes("laptop") || type.includes("notebook")) return "laptop";
  if (type.includes("desktop") || type.includes("computer") || type.includes("pc")) return "monitor";
  if (type.includes("tv") || type.includes("television")) return "tv";
  if (type.includes("printer")) return "printer";
  if (type.includes("camera")) return "camera";
  if (type.includes("speaker") || type.includes("audio")) return "speaker";
  if (type.includes("iot") || type.includes("smart")) return "cpu";

  // Check vendor
  if (vendor.includes("apple")) return "smartphone";
  if (vendor.includes("samsung")) return "smartphone";
  if (vendor.includes("google")) return "smartphone";
  if (vendor.includes("amazon")) return "cpu";
  if (vendor.includes("raspberry")) return "cpu";
  if (vendor.includes("intel") || vendor.includes("dell") || vendor.includes("hp") || vendor.includes("lenovo")) return "monitor";
  if (vendor.includes("cisco") || vendor.includes("netgear") || vendor.includes("tp-link") || vendor.includes("ubiquiti")) return "router";
  if (vendor.includes("sonos") || vendor.includes("bose")) return "speaker";

  // Check hostname
  if (hostname.includes("iphone") || hostname.includes("android")) return "smartphone";
  if (hostname.includes("ipad")) return "tablet";
  if (hostname.includes("macbook") || hostname.includes("laptop")) return "laptop";
  if (hostname.includes("imac") || hostname.includes("desktop")) return "monitor";

  return "help-circle";
}

export function getStatusColor(isOnline: boolean): string {
  return isOnline ? "text-emerald-500" : "text-slate-400";
}

export function getStatusBgColor(isOnline: boolean): string {
  return isOnline ? "bg-emerald-500" : "bg-slate-400";
}

export function timeAgo(date: string | Date): string {
  const now = new Date();
  const past = new Date(date);
  const diffMs = now.getTime() - past.getTime();
  
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return "Just now";
}
