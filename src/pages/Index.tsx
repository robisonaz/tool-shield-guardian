import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, RefreshCw, Settings, LogOut, Plus } from "lucide-react";
import { ToolTable } from "@/components/ToolTable";
import { DashboardStats } from "@/components/DashboardStats";
import { Button } from "@/components/ui/button";
import { addTool, getTools, removeTool, recheckTool, updateTool, addSubVersionToTool, removeSubVersion, type ToolEntry } from "@/lib/tools-data";
import { useAuth } from "@/hooks/useAuth";
import { toast } from "sonner";
import { motion } from "framer-motion";

const Index = () => {
  const [tools, setTools] = useState<ToolEntry[]>([]);
  const [rechecking, setRechecking] = useState(false);
  const navigate = useNavigate();
  const { isAdmin, signOut, user } = useAuth();

  const loadTools = async () => {
    const data = await getTools();
    setTools(data);
  };

  useEffect(() => {
    loadTools();
  }, []);

  const handleAdd = async (name: string, version: string, sourceUrl?: string) => {
    toast.info(`Buscando CVEs para "${name} ${version}" na base NVD/NIST...`);
    
    try {
      const entry = await addTool(name, version, sourceUrl);
      await loadTools();

      if (entry.is_outdated === null) {
        toast.warning(`"${name}" não encontrada na base de versões.`);
      } else if (entry.is_outdated) {
        toast.error(`"${name} ${version}" está desatualizada! Última: ${entry.latest_version}`);
      } else {
        toast.success(`"${name} ${version}" está atualizada!`);
      }

      if (entry.cves.length > 0) {
        toast.error(`${entry.cves.length} CVE(s) encontrada(s) para ${name} ${version}!`);
      } else {
        toast.success(`Nenhuma CVE encontrada para ${name} ${version}.`);
      }
    } catch (err) {
      console.error("Erro ao cadastrar:", err);
      toast.error("Erro ao cadastrar ferramenta.");
    }
  };

  const handleRemove = async (id: string) => {
    try {
      await removeTool(id);
      await loadTools();
      toast.info("Ferramenta removida.");
    } catch (err) {
      console.error("Erro ao remover:", err);
      toast.error("Erro ao remover ferramenta.");
    }
  };

  const handleEdit = async (id: string, name: string, version: string, sourceUrl?: string) => {
    toast.info(`Atualizando "${name} ${version}"...`);
    try {
      await updateTool(id, name, version, sourceUrl);
      await loadTools();
      toast.success(`"${name} ${version}" atualizada com sucesso!`);
    } catch (err) {
      console.error("Erro ao atualizar:", err);
      toast.error("Erro ao atualizar ferramenta.");
    }
  };

  const handleAddSubVersion = async (toolId: string, toolName: string, version: string) => {
    toast.info(`Buscando CVEs para "${toolName} ${version}"...`);
    try {
      const sv = await addSubVersionToTool(toolId, toolName, version);
      await loadTools();
      if (sv.cves.length > 0) {
        toast.error(`${sv.cves.length} CVE(s) encontrada(s) para ${toolName} ${version}!`);
      } else {
        toast.success(`Nenhuma CVE para ${toolName} ${version}.`);
      }
    } catch (err) {
      console.error("Erro ao adicionar sub-versão:", err);
      toast.error("Erro ao adicionar sub-versão.");
    }
  };

  const handleRemoveSubVersion = async (toolId: string, versionId: string) => {
    try {
      await removeSubVersion(toolId, versionId);
      await loadTools();
      toast.info("Sub-versão removida.");
    } catch (err) {
      console.error("Erro ao remover sub-versão:", err);
      toast.error("Erro ao remover sub-versão.");
    }
  };

  const handleRecheckAll = async () => {
    if (tools.length === 0) return;

    setRechecking(true);
    toast.info(`Verificando ${tools.length} ferramenta(s)...`);

    for (const tool of tools) {
      try {
        await recheckTool(tool);
      } catch (err) {
        console.error(`Failed to recheck ${tool.name}:`, err);
      }
    }

    setRechecking(false);
    await loadTools();
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
          <div className="ml-auto flex items-center gap-3">
            <Button
              onClick={() => navigate("/add-tool")}
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/80 glow-primary"
            >
              <Plus className="h-4 w-4 mr-1.5" />
              Cadastrar Ferramenta
            </Button>
            <span className="inline-flex h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
            <span className="text-xs text-muted-foreground">{user?.email}</span>
            {isAdmin && (
              <Button variant="ghost" size="icon" onClick={() => navigate("/settings")} title="Configurações">
                <Settings className="h-4 w-4" />
              </Button>
            )}
            <Button variant="ghost" size="icon" onClick={signOut} title="Sair">
              <LogOut className="h-4 w-4" />
            </Button>
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
