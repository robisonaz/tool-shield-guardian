import { useState } from "react";
import { Trash2, ChevronDown, ChevronRight, Shield, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ToolEntry } from "@/lib/tools-data";
import { motion, AnimatePresence } from "framer-motion";

interface ToolTableProps {
  tools: ToolEntry[];
  onRemove: (id: string) => void;
}

function ToolRow({ tool, onRemove }: { tool: ToolEntry; onRemove: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const status = tool.isOutdated === null ? "unknown" : tool.isOutdated ? "outdated" : "current";

  return (
    <>
      <tr
        className="border-b border-border hover:bg-secondary/50 cursor-pointer transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          {tool.cves.length > 0 ? (
            expanded ? <ChevronDown className="h-4 w-4 text-primary" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />
          ) : (
            <span className="w-4 inline-block" />
          )}
        </td>
        <td className="px-4 py-3 font-medium">{tool.name}</td>
        <td className="px-4 py-3 text-accent">{tool.version}</td>
        <td className="px-4 py-3 text-muted-foreground">{tool.latestVersion || "—"}</td>
        <td className="px-4 py-3"><StatusBadge status={status} /></td>
        <td className="px-4 py-3">
          {tool.cves.length > 0 ? (
            <span className="flex items-center gap-1.5 text-destructive">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span className="text-sm font-medium">{tool.cves.length} CVE{tool.cves.length > 1 ? "s" : ""}</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-success">
              <Shield className="h-3.5 w-3.5" />
              <span className="text-sm">Nenhum</span>
            </span>
          )}
        </td>
        <td className="px-4 py-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={(e) => { e.stopPropagation(); onRemove(tool.id); }}
            className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-8 w-8 p-0"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </td>
      </tr>
      <AnimatePresence>
        {expanded && tool.cves.length > 0 && (
          <tr>
            <td colSpan={7} className="p-0">
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="px-6 py-4 bg-secondary/30 border-b border-border">
                  <h4 className="text-xs font-sans font-semibold text-destructive mb-3 tracking-wider uppercase">
                    Vulnerabilidades Conhecidas
                  </h4>
                  <div className="space-y-2">
                    {tool.cves.map(cve => (
                      <div key={cve.id} className="flex items-start gap-3 p-3 rounded bg-card border border-border">
                        <SeverityBadge severity={cve.severity} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sm font-mono text-accent hover:underline"
                              onClick={e => e.stopPropagation()}
                            >
                              {cve.id}
                            </a>
                            <span className="text-xs text-muted-foreground">{cve.publishedDate}</span>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{cve.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

export function ToolTable({ tools, onRemove }: ToolTableProps) {
  if (tools.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-12 text-center">
        <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-40" />
        <p className="text-muted-foreground text-sm">Nenhuma ferramenta cadastrada.</p>
        <p className="text-muted-foreground text-xs mt-1">Adicione uma ferramenta acima para começar.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-secondary/50">
              <th className="px-4 py-3 w-8" />
              <th className="px-4 py-3 text-left text-xs font-sans font-semibold text-muted-foreground uppercase tracking-wider">Ferramenta</th>
              <th className="px-4 py-3 text-left text-xs font-sans font-semibold text-muted-foreground uppercase tracking-wider">Versão</th>
              <th className="px-4 py-3 text-left text-xs font-sans font-semibold text-muted-foreground uppercase tracking-wider">Última</th>
              <th className="px-4 py-3 text-left text-xs font-sans font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
              <th className="px-4 py-3 text-left text-xs font-sans font-semibold text-muted-foreground uppercase tracking-wider">CVEs</th>
              <th className="px-4 py-3 w-12" />
            </tr>
          </thead>
          <tbody>
            {tools.map((tool, i) => (
              <ToolRow key={tool.id} tool={tool} onRemove={onRemove} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
