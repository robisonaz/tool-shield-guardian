import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: "critical" | "high" | "medium" | "low";
}

const config = {
  critical: { label: "CRITICAL", className: "bg-destructive/20 text-destructive border-destructive/40 animate-pulse-glow" },
  high: { label: "HIGH", className: "bg-high/15 text-high border-high/30" },
  medium: { label: "MEDIUM", className: "bg-warning/20 text-warning border-warning/30" },
  low: { label: "LOW", className: "bg-muted text-muted-foreground border-border" },
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const c = config[severity];
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border tracking-wider", c.className)}>
      {c.label}
    </span>
  );
}
