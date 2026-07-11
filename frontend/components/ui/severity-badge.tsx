import { cn, severityColor } from "@/lib/utils";

export function SeverityBadge({ value, className }: { value?: string | null; className?: string }) {
  const v = (value || "none").toLowerCase();
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold uppercase tracking-wide",
        severityColor(v),
        className,
      )}
    >
      {v}
    </span>
  );
}
