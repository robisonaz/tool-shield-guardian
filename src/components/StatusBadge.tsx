import { cn } from "@/lib/utils";

interface StatusBadgeProps {
  status: "outdated" | "current" | "unknown";
}

const config = {
  outdated: { label: "DESATUALIZADO", className: "bg-destructive/20 text-destructive border-destructive/30" },
  current: { label: "ATUALIZADO", className: "bg-success/20 text-success border-success/30" },
  unknown: { label: "DESCONHECIDO", className: "bg-warning/20 text-warning border-warning/30" },
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const c = config[status];
  return (
    <span className={cn("inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-medium border", c.className)}>
      {c.label}
    </span>
  );
}
