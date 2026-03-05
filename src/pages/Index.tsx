import { useState, useEffect } from "react";
import { ShieldCheck, RefreshCw } from "lucide-react";
import { AddToolForm } from "@/components/AddToolForm";
import { ToolTable } from "@/components/ToolTable";
import { DashboardStats } from "@/components/DashboardStats";
import { Button } from "@/components/ui/button";
import { addTool, getStoredTools, removeTool, recheckTool, updateTool, type ToolEntry } from "@/lib/tools-data";
import { toast } from "sonner";
import { motion } from "framer-motion";

const Index = () => {
  const [tools, setTools] = useState<ToolEntry[]>([]);
  const [rechecking, setRechecking] = useState(false);

  useEffect(() => {
    setTools(getStoredTools());
  }, []);

  const handleAdd = async (name: string, version: string) => {
    toast.info(`Buscando CVEs para "${name} ${version}" na base NVD/NIST...`);
    
    const entry = await addTool(name, version);
    setTools(getStoredTools());

    if (entry.isOutdated === null) {
      toast.warning(`"${name}" não encontrada na base de versões.`);
    } else if (entry.isOutdated) {
      toast.error(`"${name} ${version}" está desatualizada! Última: ${entry.latestVersion}`);
    } else {
      toast.success(`"${name} ${version}" está atualizada!`);
    }

    if (entry.cves.length > 0) {
      toast.error(`${entry.cves.length} CVE(s) encontrada(s) para ${name} ${version}!`);
    } else {
      toast.success(`Nenhuma CVE encontrada para ${name} ${version}.`);
    }
  };

  const handleRemove = (id: string) => {
    removeTool(id);
    setTools(getStoredTools());
    toast.info("Ferramenta removida.");
  };

  const handleEdit = async (id: string, name: string, version: string) => {
    toast.info(`Atualizando "${name} ${version}"...`);
    await updateTool(id, name, version);
    setTools(getStoredTools());
    toast.success(`"${name} ${version}" atualizada com sucesso!`);
  };

  const handleRecheckAll = async () => {
    const currentTools = getStoredTools();
    if (currentTools.length === 0) return;

    setRechecking(true);
    toast.info(`Verificando ${currentTools.length} ferramenta(s)...`);

    // Process sequentially to avoid rate limiting
    for (let i = 0; i < currentTools.length; i++) {
      try {
        await recheckTool(currentTools[i]);
        setTools(getStoredTools());
      } catch (err) {
        console.error(`Failed to recheck ${currentTools[i].name}:`, err);
      }
    }

    setRechecking(false);
    setTools(getStoredTools());
    toast.success("Checagem concluída!");
  };

  return (
    <div className="min-h-screen bg-background scanline">
      {/* Header */}
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
            <ShieldCheck className="h-6 w-6 text-primary text-glow" />
          </div>
          <div>
            <h1 className="text-xl font-sans font-bold text-foreground">
              SecVersions
            </h1>
            <p className="text-xs text-muted-foreground">Monitoramento de versões e vulnerabilidades</p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="inline-flex h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
            <span className="text-xs text-muted-foreground">Online</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 space-y-6">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <DashboardStats tools={tools} />
        </motion.div>

        <AddToolForm onAdd={handleAdd} />

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="flex items-center gap-2 mb-3">
            <h2 className="text-lg font-sans font-semibold text-foreground">Ferramentas Cadastradas</h2>
            <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded">
              {tools.length}
            </span>
            {tools.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleRecheckAll}
                disabled={rechecking}
                className="ml-auto border-primary/30 text-primary hover:bg-primary/10 hover:text-primary"
              >
                <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${rechecking ? "animate-spin" : ""}`} />
                {rechecking ? "Verificando..." : "Rechecar Tudo"}
              </Button>
            )}
          </div>
          <ToolTable tools={tools} onRemove={handleRemove} onEdit={handleEdit} />
        </motion.div>
      </main>
    </div>
  );
};

export default Index;
