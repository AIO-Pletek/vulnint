import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(sev?: string | null): string {
  switch ((sev || "").toLowerCase()) {
    case "critical": return "bg-sev-critical text-white";
    case "high":     return "bg-sev-high text-white";
    case "medium":   return "bg-sev-medium text-black";
    case "low":      return "bg-sev-low text-white";
    default:         return "bg-sev-none text-white";
  }
}

export function formatDate(input?: string | null) {
  if (!input) return "—";
  const d = new Date(input);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

export function formatRelative(input?: string | null) {
  if (!input) return "—";
  const d = new Date(input);
  const diff = Date.now() - d.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}
