import { useState } from "react";
import { Trash2, ChevronDown, ChevronRight, Shield, AlertTriangle, ArrowUpCircle, Clock, Star, Pencil, Check, X, Globe, Radar, Plus, Loader2, Layers, ArrowRightLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/StatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ToolEntry, SubVersionEntry, ToolCategory } from "@/lib/tools-data";
import { AVAILABLE_TOOLS, CATEGORY_LABELS } from "@/lib/tools-data";
import { motion, AnimatePresence } from "framer-motion";

interface ToolTableProps {
  tools: ToolEntry[];
  onRemove: (id: string) => void;
  onEdit: (id: string, name: string, version: string, sourceUrl?: string) => void;
  onAddSubVersion?: (toolId: string, toolName: string, version: string) => void;
  onRemoveSubVersion?: (toolId: string, versionId: string) => void;
  onChangeCategory?: (id: string, category: ToolCategory) => void;
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

function CvesSummary({ cves }: { cves: { id: string; severity: "critical" | "high" | "medium" | "low" }[] }) {
  if (cves.length === 0) {
    return (
      <span className="flex items-center gap-1.5 text-success">
        <Shield className="h-3.5 w-3.5" />
        <span className="text-sm">Nenhum</span>
      </span>
    );
  }
  const maxSeverity = cves.reduce((max, cve) => {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return order[cve.severity] > order[max] ? cve.severity : max;
  }, "low" as "critical" | "high" | "medium" | "low");
  const config = {
    critical: { color: "text-destructive", icon: AlertTriangle },
    high: { color: "text-high", icon: AlertTriangle },
    medium: { color: "text-warning", icon: AlertTriangle },
    low: { color: "text-muted-foreground", icon: Shield },
  };
  const { color, icon: Icon } = config[maxSeverity];
  return (
    <div className="flex items-center gap-1.5">
      <Icon className={`h-3.5 w-3.5 ${color}`} />
      <span className="text-sm font-medium text-destructive">{cves.length} CVE{cves.length > 1 ? "s" : ""}</span>
      <div className="flex items-center gap-0.5 ml-1">
        {cves.some(c => c.severity === "critical") && <span className="h-2 w-2 rounded-full bg-destructive" title="Critical" />}
        {cves.some(c => c.severity === "high") && <span className="h-2 w-2 rounded-full bg-high" title="High" />}
        {cves.some(c => c.severity === "medium") && <span className="h-2 w-2 rounded-full bg-warning" title="Medium" />}
        {cves.some(c => c.severity === "low") && <span className="h-2 w-2 rounded-full bg-muted-foreground" title="Low" />}
      </div>
    </div>
  );
}

function SubVersionRow({ sv, toolName, onRemove }: { sv: SubVersionEntry; toolName: string; onRemove: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const status = sv.is_outdated === null ? "unknown" : sv.is_outdated ? "outdated" : "current";
  const isDiscoverySource = !!sv.source_url && /^https?:\/\/\d+\.\d+\.\d+\.\d+(?::\d+)?\/?$/i.test(sv.source_url);
  const sourceLabel = (() => {
    if (!sv.source_url) return null;
    try {
      const url = new URL(sv.source_url);
      return url.port ? `${url.hostname}:${url.port}` : url.hostname;
    } catch {
      return sv.source_url;
    }
  })();

  return (
    <>
      <tr
        className="border-b border-border/50 hover:bg-secondary/30 cursor-pointer transition-colors bg-secondary/10"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-2 pl-10">
          {sv.cves.length > 0 || sv.latest_patch_for_cycle ? (
            expanded ? <ChevronDown className="h-3 w-3 text-primary" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />
          ) : <span className="w-3 inline-block" />}
        </td>
        <td className="px-4 py-2 text-xs text-muted-foreground italic">
          <div className="flex items-center gap-2 flex-wrap">
            <Layers className="h-3 w-3 text-muted-foreground/60" />
            <span>Sub-versão</span>
            {sourceLabel && (
              <span
                title={`${toolName} em ${sv.source_url}`}
                className="inline-flex items-center gap-1 rounded border border-accent/20 bg-accent/10 px-1.5 py-0.5 text-[11px] not-italic text-accent"
              >
                {isDiscoverySource ? <Radar className="h-3 w-3" /> : <Globe className="h-3 w-3" />}
                {sourceLabel}
              </span>
            )}
            <LtsBadge lts={sv.lts} />
            <EolBadge eol={sv.eol} />
          </div>
        </td>
        <td className="px-4 py-2 text-accent text-sm">{sv.version}</td>
        <td className="px-4 py-2 text-muted-foreground text-sm">{sv.latest_version || "—"}</td>
        <td className="px-4 py-2"><StatusBadge status={status} /></td>
        <td className="px-4 py-2"><CvesSummary cves={sv.cves} /></td>
        <td className="px-4 py-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={(e) => { e.stopPropagation(); onRemove(); }}
            className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-7 w-7 p-0"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </td>
      </tr>
      <AnimatePresence>
        {expanded && (sv.cves.length > 0 || sv.latest_patch_for_cycle) && (
          <tr>
            <td colSpan={7} className="p-0">
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="px-8 py-3 bg-secondary/20 border-b border-border/50 space-y-3">
                  {sv.latest_patch_for_cycle && (
                    <div className="rounded bg-card border border-border p-3">
                      <h4 className="text-xs font-sans font-semibold text-primary mb-2 tracking-wider uppercase flex items-center gap-1.5">
                        <ArrowUpCircle className="h-3.5 w-3.5" />
                        Versão Recomendada
                      </h4>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
                        <div>
                          <span className="text-xs text-muted-foreground block">Corrigida (ciclo {sv.cycle_label})</span>
                          <span className={`font-mono font-semibold ${sv.is_patch_outdated ? "text-warning" : "text-success"}`}>{sv.latest_patch_for_cycle}</span>
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground block">Última Estável</span>
                          <span className="font-mono font-semibold text-primary">{sv.latest_version}</span>
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground block">Status do Ciclo</span>
                          {sv.eol === true || (typeof sv.eol === "string" && new Date(sv.eol) < new Date()) ? (
                            <span className="text-destructive text-xs font-medium">⚠ Fim de vida (EOL)</span>
                          ) : sv.eol === false ? (
                            <span className="text-success text-xs font-medium">✓ Suportado</span>
                          ) : typeof sv.eol === "string" ? (
                            <span className="text-warning text-xs font-medium">Suporte até {sv.eol}</span>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                  {sv.cves.length > 0 && (
                    <>
                      <h4 className="text-xs font-sans font-semibold text-destructive tracking-wider uppercase">Vulnerabilidades</h4>
                      <div className="space-y-2">
                        {sv.cves.map(cve => (
                          <div key={cve.id} className="flex items-start gap-3 p-2 rounded bg-card border border-border">
                            <SeverityBadge severity={cve.severity} />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="text-xs font-mono text-accent hover:underline" onClick={e => e.stopPropagation()}>{cve.id}</a>
                                <span className="text-xs text-muted-foreground">{cve.publishedDate}</span>
                              </div>
                              <p className="text-xs text-muted-foreground mt-0.5">{cve.description}</p>
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

function ToolRow({ tool, onRemove, onEdit, onAddSubVersion, onRemoveSubVersion }: {
  tool: ToolEntry;
  onRemove: (id: string) => void;
  onEdit: (id: string, name: string, version: string, sourceUrl?: string) => void;
  onAddSubVersion?: (toolId: string, toolName: string, version: string) => void;
  onRemoveSubVersion?: (toolId: string, versionId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(tool.name);
  const [editVersion, setEditVersion] = useState(tool.version);
  const [editUrl, setEditUrl] = useState(tool.source_url || "");
  const [newSubVersion, setNewSubVersion] = useState("");
  const [savingSubVersion, setSavingSubVersion] = useState(false);
  const status = tool.is_outdated === null ? "unknown" : tool.is_outdated ? "outdated" : "current";

  const hasDetails = tool.cves.length > 0 || tool.latest_patch_for_cycle || (tool.sub_versions && tool.sub_versions.length > 0);

  const handleSaveEdit = () => {
    if (!editName.trim() || !editVersion.trim()) return;
    onEdit(tool.id, editName.trim(), editVersion.trim(), editUrl.trim() || undefined);
    setEditing(false);
  };

  const handleCancelEdit = () => {
    setEditName(tool.name);
    setEditVersion(tool.version);
    setEditUrl(tool.source_url || "");
    setEditing(false);
  };

  const handleAddSubVersion = async () => {
    if (!newSubVersion.trim() || !onAddSubVersion) return;
    setSavingSubVersion(true);
    try {
      await onAddSubVersion(tool.id, tool.name, newSubVersion.trim());
    } catch (err) {
      console.error("Erro ao adicionar sub-versão no ToolRow:", err);
    }
    setNewSubVersion("");
    setSavingSubVersion(false);
  };

  // Aggregate all CVEs (main + sub-versions) for display
  const allCves = [
    ...tool.cves,
    ...(tool.sub_versions?.flatMap(sv => sv.cves) || []),
  ];

  return (
    <>
      <tr
        className="border-b border-border hover:bg-secondary/50 cursor-pointer transition-colors"
        onClick={() => !editing && setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          {hasDetails ? (
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
              {tool.source_url ? (
                /^https?:\/\/\d+\.\d+\.\d+\.\d+:\d+\/?$/.test(tool.source_url) ? (
                  <span title={`Descoberto via Discovery: ${tool.source_url}`}>
                    <Radar className="h-3.5 w-3.5 text-accent" />
                  </span>
                ) : (
                  <span title={`Monitorado via URL: ${tool.source_url}`}>
                    <Globe className="h-3.5 w-3.5 text-primary" />
                  </span>
                )
              ) : null}
              {tool.sub_versions && tool.sub_versions.length > 0 && (
                <span className="inline-flex items-center gap-1 text-xs px-1.5 py-0.5 rounded bg-accent/15 text-accent border border-accent/20">
                  <Layers className="h-3 w-3" />
                  +{tool.sub_versions.length}
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
            <div className="space-y-1">
              <Input
                value={editVersion}
                onChange={(e) => setEditVersion(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Enter" && handleSaveEdit()}
                className="h-7 text-sm bg-secondary border-border w-24"
                placeholder="Versão"
              />
              <Input
                value={editUrl}
                onChange={(e) => setEditUrl(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Enter" && handleSaveEdit()}
                className="h-7 text-sm bg-secondary border-border w-40"
                placeholder="URL (opcional)"
              />
            </div>
          ) : (
            tool.version
          )}
        </td>
        <td className="px-4 py-3 text-muted-foreground">{tool.latest_version || "—"}</td>
        <td className="px-4 py-3"><StatusBadge status={status} /></td>
        <td className="px-4 py-3"><CvesSummary cves={allCves} /></td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1">
            {editing ? (
              <>
                <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); handleSaveEdit(); }} className="text-success hover:text-success hover:bg-success/10 h-8 w-8 p-0">
                  <Check className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); handleCancelEdit(); }} className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-8 w-8 p-0">
                  <X className="h-4 w-4" />
                </Button>
              </>
            ) : (
              <>
                <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); setEditing(true); setExpanded(true); }} className="text-muted-foreground hover:text-accent hover:bg-accent/10 h-8 w-8 p-0" title="Editar">
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); onRemove(tool.id); }} className="text-muted-foreground hover:text-destructive hover:bg-destructive/10 h-8 w-8 p-0" title="Remover">
                  <Trash2 className="h-4 w-4" />
                </Button>
              </>
            )}
          </div>
        </td>
      </tr>
      <AnimatePresence>
        {expanded && (
          <>
            {/* Sub-versions */}
            {tool.sub_versions && tool.sub_versions.map(sv => (
              <SubVersionRow
                key={sv.id}
                sv={sv}
                toolName={tool.name}
                onRemove={() => onRemoveSubVersion?.(tool.id, sv.id)}
              />
            ))}

            {/* Add sub-version form — always visible when editing */}
            {editing && onAddSubVersion && (
              <tr>
                <td colSpan={7} className="p-0">
                  <div className="px-6 py-3 bg-primary/5 border-b border-border flex items-center gap-3">
                    <Layers className="h-4 w-4 text-primary ml-4" />
                    <span className="text-xs text-muted-foreground">Adicionar sub-versão para <strong>{tool.name}</strong>:</span>
                    <Input
                      value={newSubVersion}
                      onChange={(e) => setNewSubVersion(e.target.value)}
                      onClick={(e) => e.stopPropagation()}
                      onKeyDown={(e) => e.key === "Enter" && handleAddSubVersion()}
                      placeholder="Ex: 7.33.0"
                      className="h-7 text-sm bg-secondary border-border w-32"
                    />
                    <Button size="sm" onClick={(e) => { e.stopPropagation(); handleAddSubVersion(); }} disabled={savingSubVersion || !newSubVersion.trim()} className="h-7 text-xs bg-primary text-primary-foreground hover:bg-primary/80">
                      {savingSubVersion ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Plus className="h-3 w-3 mr-1" />}
                      Adicionar
                    </Button>
                  </div>
                </td>
              </tr>
            )}

            {/* Main tool details */}
            {(tool.cves.length > 0 || tool.latest_patch_for_cycle) && (
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
                      {tool.latest_patch_for_cycle && (
                        <div className="rounded bg-card border border-border p-3">
                          <h4 className="text-xs font-sans font-semibold text-primary mb-2 tracking-wider uppercase flex items-center gap-1.5">
                            <ArrowUpCircle className="h-3.5 w-3.5" />
                            Versão Recomendada ({tool.version})
                          </h4>
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
                            <div>
                              <span className="text-xs text-muted-foreground block">Corrigida (ciclo {tool.cycle_label})</span>
                              <span className={`font-mono font-semibold ${tool.is_patch_outdated ? "text-warning" : "text-success"}`}>{tool.latest_patch_for_cycle}</span>
                              {tool.is_patch_outdated && <span className="text-xs text-warning ml-2">⬆ atualização disponível</span>}
                            </div>
                            <div>
                              <span className="text-xs text-muted-foreground block">Última Estável</span>
                              <span className="font-mono font-semibold text-primary">{tool.latest_version}</span>
                            </div>
                            <div>
                              <span className="text-xs text-muted-foreground block">Status do Ciclo</span>
                              {tool.eol === true || (typeof tool.eol === "string" && new Date(tool.eol) < new Date()) ? (
                                <span className="text-destructive text-xs font-medium">⚠ Fim de vida (EOL)</span>
                              ) : tool.eol === false ? (
                                <span className="text-success text-xs font-medium">✓ Suportado</span>
                              ) : typeof tool.eol === "string" ? (
                                <span className="text-warning text-xs font-medium">Suporte até {tool.eol}</span>
                              ) : (
                                <span className="text-muted-foreground text-xs">—</span>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                      {tool.cves.length > 0 && (
                        <>
                          <h4 className="text-xs font-sans font-semibold text-destructive tracking-wider uppercase">
                            Vulnerabilidades ({tool.version})
                          </h4>
                          <div className="space-y-2">
                            {tool.cves.map(cve => (
                              <div key={cve.id} className="flex items-start gap-3 p-3 rounded bg-card border border-border">
                                <SeverityBadge severity={cve.severity} />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2">
                                    <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer" className="text-sm font-mono text-accent hover:underline" onClick={e => e.stopPropagation()}>{cve.id}</a>
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
          </>
        )}
      </AnimatePresence>
    </>
  );
}

export function ToolTable({ tools, onRemove, onEdit, onAddSubVersion, onRemoveSubVersion }: ToolTableProps) {
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
              <th className="px-4 py-3 w-28" />
            </tr>
          </thead>
          <tbody>
            {tools.map((tool) => (
              <ToolRow
                key={tool.id}
                tool={tool}
                onRemove={onRemove}
                onEdit={onEdit}
                onAddSubVersion={onAddSubVersion}
                onRemoveSubVersion={onRemoveSubVersion}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
