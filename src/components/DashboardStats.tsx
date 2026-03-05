import { Shield, AlertTriangle, CheckCircle, HelpCircle } from "lucide-react";
import type { ToolEntry } from "@/lib/tools-data";
import { motion } from "framer-motion";

interface DashboardStatsProps {
  tools: ToolEntry[];
}

export function DashboardStats({ tools }: DashboardStatsProps) {
  const total = tools.length;
  const outdated = tools.filter(t => t.isOutdated === true).length;
  const upToDate = tools.filter(t => t.isOutdated === false).length;
  const totalCves = tools.reduce((acc, t) => acc + t.cves.length, 0);
  const criticalCves = tools.reduce((acc, t) => acc + t.cves.filter(c => c.severity === "critical").length, 0);

  const stats = [
    { label: "Total", value: total, icon: Shield, color: "text-primary" },
    { label: "Atualizadas", value: upToDate, icon: CheckCircle, color: "text-success" },
    { label: "Desatualizadas", value: outdated, icon: AlertTriangle, color: "text-warning" },
    { label: "CVEs Encontradas", value: totalCves, icon: AlertTriangle, color: "text-destructive", sub: criticalCves > 0 ? `${criticalCves} críticas` : undefined },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat, i) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.1 }}
          className="rounded-lg border border-border bg-card p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-sans text-muted-foreground uppercase tracking-wider">{stat.label}</span>
            <stat.icon className={`h-4 w-4 ${stat.color}`} />
          </div>
          <p className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</p>
          {stat.sub && <p className="text-xs text-destructive mt-1">{stat.sub}</p>}
        </motion.div>
      ))}
    </div>
  );
}
