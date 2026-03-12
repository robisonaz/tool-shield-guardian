import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Radar, ArrowLeft, Search, Loader2, Plus, Check, Globe, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";
import { discoveryScan, type DiscoveryResult } from "@/lib/api-client";
import { addTool } from "@/lib/tools-data";

const Discovery = () => {
  const navigate = useNavigate();
  const [cidr, setCidr] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<DiscoveryResult[]>([]);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [registering, setRegistering] = useState(false);
  const [scanInfo, setScanInfo] = useState<{ total_hosts: number; total_ports_scanned: number } | null>(null);

  const handleScan = async () => {
    if (!cidr.trim()) {
      toast.error("Informe um IP ou CIDR");
      return;
    }

    setScanning(true);
    setResults([]);
    setSelected(new Set());
    setScanInfo(null);

    try {
      const data = await discoveryScan(cidr.trim());
      setResults(data.results);
      setScanInfo({ total_hosts: data.total_hosts, total_ports_scanned: data.total_ports_scanned });

      if (data.results.length === 0) {
        toast.info("Nenhuma porta aberta encontrada no range.");
      } else {
        toast.success(`${data.results.length} porta(s) aberta(s) encontrada(s)!`);
      }
    } catch (err: any) {
      toast.error(err.message || "Erro ao realizar scan");
    } finally {
      setScanning(false);
    }
  };

  const toggleSelect = (idx: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const selectAllWithTool = () => {
    const indices = results
      .map((r, i) => (r.tool ? i : -1))
      .filter((i) => i >= 0);
    setSelected(new Set(indices));
  };

  const handleRegister = async () => {
    if (selected.size === 0) {
      toast.error("Selecione ao menos um serviço");
      return;
    }

    setRegistering(true);
    let count = 0;

    for (const idx of selected) {
      const r = results[idx];
      if (!r.tool) continue;

      try {
        const sourceUrl = `http://${r.ip}:${r.port}`;
        await addTool(r.tool, r.version || "unknown", sourceUrl);
        count++;
      } catch (err) {
        console.error(`Erro ao cadastrar ${r.tool}:`, err);
      }
    }

    setRegistering(false);
    if (count > 0) {
      toast.success(`${count} ferramenta(s) cadastrada(s)!`);
    }
  };

  const toolResults = results.filter((r) => r.tool);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate("/")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="p-2 rounded-lg bg-accent/10 border border-accent/20">
            <Radar className="h-5 w-5 text-accent" />
          </div>
          <div>
            <h1 className="text-xl font-sans font-bold text-foreground">Network Discovery</h1>
            <p className="text-xs text-muted-foreground">Escaneie ranges de IP para descobrir serviços</p>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 space-y-6">
        {/* Scan Input */}
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="border-border bg-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Search className="h-4 w-4 text-primary" />
                Configurar Scan
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3">
                <Input
                  placeholder="IP ou CIDR (ex: 192.168.1.0/24 ou 10.0.0.1)"
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !scanning && handleScan()}
                  className="flex-1 bg-muted border-border font-mono text-sm"
                  disabled={scanning}
                />
                <Button
                  onClick={handleScan}
                  disabled={scanning || !cidr.trim()}
                  className="bg-primary text-primary-foreground hover:bg-primary/80 min-w-[140px]"
                >
                  {scanning ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Escaneando...
                    </>
                  ) : (
                    <>
                      <Radar className="h-4 w-4 mr-2" />
                      Iniciar Scan
                    </>
                  )}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Escaneia portas comuns (21, 22, 80, 443, 3000, 8080, 9090, etc). Máximo: /16 ou 1024 hosts.
              </p>
            </CardContent>
          </Card>
        </motion.div>

        {/* Scanning Animation */}
        <AnimatePresence>
          {scanning && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center py-12 gap-4"
            >
              <div className="relative">
                <div className="h-20 w-20 rounded-full border-2 border-primary/30 animate-ping absolute inset-0" />
                <div className="h-20 w-20 rounded-full border-2 border-primary/50 flex items-center justify-center">
                  <Radar className="h-8 w-8 text-primary animate-pulse" />
                </div>
              </div>
              <p className="text-muted-foreground text-sm">Escaneando rede...</p>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results */}
        {!scanning && results.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
            {/* Summary */}
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">
                  {scanInfo?.total_hosts} host(s) • {results.length} porta(s) aberta(s) • {toolResults.length} serviço(s) identificado(s)
                </span>
              </div>
              <div className="ml-auto flex gap-2">
                {toolResults.length > 0 && (
                  <Button variant="outline" size="sm" onClick={selectAllWithTool} className="border-accent/30 text-accent">
                    <Check className="h-3.5 w-3.5 mr-1.5" />
                    Selecionar Identificados ({toolResults.length})
                  </Button>
                )}
                <Button
                  size="sm"
                  onClick={handleRegister}
                  disabled={selected.size === 0 || registering}
                  className="bg-primary text-primary-foreground hover:bg-primary/80"
                >
                  {registering ? (
                    <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                  ) : (
                    <Plus className="h-3.5 w-3.5 mr-1.5" />
                  )}
                  Cadastrar Selecionados ({selected.size})
                </Button>
              </div>
            </div>

            {/* Results Table */}
            <Card className="border-border bg-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-muted/50">
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground w-10"></th>
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground">IP</th>
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground">Porta</th>
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground">Serviço</th>
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground">Ferramenta</th>
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground">Versão</th>
                      <th className="text-left py-3 px-4 font-medium text-muted-foreground">Banner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((r, idx) => (
                      <motion.tr
                        key={`${r.ip}:${r.port}`}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.03 }}
                        className={`border-b border-border/50 hover:bg-muted/30 transition-colors cursor-pointer ${
                          selected.has(idx) ? "bg-primary/5" : ""
                        }`}
                        onClick={() => r.tool && toggleSelect(idx)}
                      >
                        <td className="py-3 px-4">
                          {r.tool && (
                            <Checkbox
                              checked={selected.has(idx)}
                              onCheckedChange={() => toggleSelect(idx)}
                            />
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs">{r.ip}</td>
                        <td className="py-3 px-4">
                          <Badge variant="outline" className="font-mono text-xs">
                            {r.port}
                          </Badge>
                        </td>
                        <td className="py-3 px-4 text-muted-foreground">{r.service}</td>
                        <td className="py-3 px-4">
                          {r.tool ? (
                            <Badge className="bg-primary/10 text-primary border-primary/20">
                              <Globe className="h-3 w-3 mr-1" />
                              {r.tool}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {r.version ? (
                            <span className="font-mono text-xs text-accent">{r.version}</span>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-xs text-muted-foreground truncate max-w-[200px]">
                          {r.banner}
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </motion.div>
        )}

        {/* Empty state after scan */}
        {!scanning && scanInfo && results.length === 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center py-16">
            <Server className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-50" />
            <p className="text-muted-foreground">Nenhuma porta aberta encontrada</p>
            <p className="text-xs text-muted-foreground mt-1">Verifique o range e tente novamente</p>
          </motion.div>
        )}
      </main>
    </div>
  );
};

export default Discovery;
