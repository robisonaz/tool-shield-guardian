import { useState } from "react";
import { Trash2, ChevronDown, ChevronRight, Shield, AlertTriangle, ArrowUpCircle, Clock, Star, Pencil, Check, X, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/StatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ToolEntry } from "@/lib/tools-data";
import { AVAILABLE_TOOLS } from "@/lib/tools-data";
import { motion, AnimatePresence } from "framer-motion";

interface ToolTableProps {
  tools: ToolEntry[];
  onRemove: (id: string) => void;
  onEdit: (id: string, name: string, version: string) => void;
}

function EolBadge({ eol }: { eol: string | boolean | null }) {
  if (eol === null || eol === undefined) return null;
  const isEol = eol === true || (typeof eol === "string" && new Date(eol) < new Date());
  if (isEol) {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/20">
        <Clock className="h-3 w-3" /> EOL
      </span>
    );
  }
  if (typeof eol === "string") {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-warning/15 text-warning border border-warning/20">
        <Clock className="h-3 w-3" /> EOL: {eol}
      </span>
    );
  }
  return null;
}

function LtsBadge({ lts }: { lts: string | boolean | null }) {
  if (!lts) return null;
  return (
    <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/20">
      <Star className="h-3 w-3" /> LTS
    </span>
  );
}

function ToolRow({ tool, onRemove, onEdit }: { tool: ToolEntry; onRemove: (id: string) => void; onEdit: (id: string, name: string, version: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(tool.name);
  const [editVersion, setEditVersion] = useState(tool.version);
  const status = tool.isOutdated === null ? "unknown" : tool.isOutdated ? "outdated" : "current";

  const handleSaveEdit = () => {
    if (!editName.trim() || !editVersion.trim()) return;
    onEdit(tool.id, editName.trim(), editVersion.trim());
    setEditing(false);
  };

  const handleCancelEdit = () => {
    setEditName(tool.name);
    setEditVersion(tool.version);
    setEditing(false);
  };

  return (
    <>
      <tr
        className="border-b border-border hover:bg-secondary/50 cursor-pointer transition-colors"
        onClick={() => !editing && setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          {(tool.cves.length > 0 || tool.latestPatchForCycle) ? (
            expanded ? <ChevronDown className="h-4 w-4 text-primary" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />
          ) : (
            <span className="w-4 inline-block" />
          )}
        </td>
        <td className="px-4 py-3 font-medium">
          {editing ? (
            <Input
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              onClick={(e) => e.stopPropagation()}
              className="h-7 text-sm bg-secondary border-border w-40"
              list="edit-tool-suggestions"
            />
          ) : (
            <div className="flex items-center gap-2">
              {tool.name}
              {tool.sourceUrl && (
                <span title={`URL: ${tool.sourceUrl}`}>
                  <Globe className="h-3 w-3 text-primary/60" />
                </span>
              )}
              <LtsBadge lts={tool.lts} />
              <EolBadge eol={tool.eol} />
            </div>
          )}
          <datalist id="edit-tool-suggestions">
            {AVAILABLE_TOOLS.map(t => <option key={t} value={t} />)}
          </datalist>
        </td>
        <td className="px-4 py-3 text-accent">
          {editing ? (
            <Input
              value={editVersion}
              onChange={(e) => setEditVersion(e.target.value)}
              onClick={(e) => e.stopPropagation()}
              onKeyDown={(e) => e.key === "Enter" && handleSaveEdit()}
              className="h-7 text-sm bg-secondary border-border w-24"
            />
          ) : (
            tool.version
          )}
        </td>
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
          <div className="flex items-center gap-1">
            {editing ? (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => { e.stopPropagation(); handleSaveEdit(); }}
                  className="text-success hover:text-success hover:bg-success/10 h-8 w-8 p-0"
                >
                  <Check className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => { e.stopPropagation(); handleCancelEdit(); }}
                  className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-8 w-8 p-0"
                >
                  <X className="h-4 w-4" />
                </Button>
              </>
            ) : (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => { e.stopPropagation(); setEditing(true); }}
                  className="text-muted-foreground hover:text-accent hover:bg-accent/10 h-8 w-8 p-0"
                >
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => { e.stopPropagation(); onRemove(tool.id); }}
                  className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-8 w-8 p-0"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </>
            )}
          </div>
        </td>
      </tr>
      <AnimatePresence>
        {expanded && (tool.cves.length > 0 || tool.latestPatchForCycle) && (
          <tr>
            <td colSpan={7} className="p-0">
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="px-6 py-4 bg-secondary/30 border-b border-border space-y-4">
                  {/* Version recommendation */}
                  {tool.latestPatchForCycle && (
                    <div className="rounded bg-card border border-border p-3">
                      <h4 className="text-xs font-sans font-semibold text-primary mb-2 tracking-wider uppercase flex items-center gap-1.5">
                        <ArrowUpCircle className="h-3.5 w-3.5" />
                        Versão Recomendada
                      </h4>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
                        <div>
                          <span className="text-xs text-muted-foreground block">Corrigida (ciclo {tool.cycleLabel})</span>
                          <span className={`font-mono font-semibold ${tool.isPatchOutdated ? "text-warning" : "text-success"}`}>
                            {tool.latestPatchForCycle}
                          </span>
                          {tool.isPatchOutdated && (
                            <span className="text-xs text-warning ml-2">⬆ atualização disponível</span>
                          )}
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground block">Última Estável</span>
                          <span className="font-mono font-semibold text-primary">{tool.latestVersion}</span>
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground block">Status do Ciclo</span>
                          <span className="flex items-center gap-1.5">
                            {tool.eol === true || (typeof tool.eol === "string" && new Date(tool.eol) < new Date()) ? (
                              <span className="text-destructive text-xs font-medium">⚠ Fim de vida (EOL)</span>
                            ) : tool.eol === false ? (
                              <span className="text-success text-xs font-medium">✓ Suportado</span>
                            ) : typeof tool.eol === "string" ? (
                              <span className="text-warning text-xs font-medium">Suporte até {tool.eol}</span>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* CVEs */}
                  {tool.cves.length > 0 && (
                    <>
                      <h4 className="text-xs font-sans font-semibold text-destructive tracking-wider uppercase">
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
                    </>
                  )}
                </div>
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

export function ToolTable({ tools, onRemove, onEdit }: ToolTableProps) {
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
              <th className="px-4 py-3 w-24" />
            </tr>
          </thead>
          <tbody>
            {tools.map((tool) => (
              <ToolRow key={tool.id} tool={tool} onRemove={onRemove} onEdit={onEdit} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
