import { useState } from "react";
import { Plus, Terminal, Globe, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AVAILABLE_TOOLS, CATEGORY_LABELS, type ToolCategory } from "@/lib/tools-data";
import { versionDetect } from "@/lib/api-client";
import { motion } from "framer-motion";
import { toast } from "sonner";

interface AddToolFormProps {
  onAdd: (name: string, version: string, sourceUrl?: string, category?: ToolCategory, description?: string) => void;
}

export function AddToolForm({ onAdd }: AddToolFormProps) {
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState<ToolCategory>("ferramenta");
  const [detecting, setDetecting] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !version.trim()) return;
    onAdd(name.trim(), version.trim(), url.trim() || undefined, category);
    setName("");
    setVersion("");
    setUrl("");
    setCategory("ferramenta");
  };

  const handleDetect = async () => {
    if (!url.trim()) {
      toast.warning("Informe uma URL para detectar.");
      return;
    }

    setDetecting(true);
    toast.info(`Detectando versão de ${url.trim()}...`);

    try {
      const data = await versionDetect(url.trim());

      if (data?.tool) {
        setName(data.tool);
        if (data.version) {
          setVersion(data.version);
          toast.success(data.message);
        } else {
          toast.warning(data.message);
        }
      } else {
        toast.warning(data?.message || "Não foi possível detectar a ferramenta.");
      }
    } catch (err) {
      console.error("Detection error:", err);
      toast.error("Falha na detecção. Verifique se a URL está acessível.");
    } finally {
      setDetecting(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-lg border border-glow bg-card p-6"
    >
      <div className="flex items-center gap-2 mb-4">
        <Terminal className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-sans font-semibold text-foreground">Cadastrar Ferramenta</h2>
      </div>

      <div className="flex flex-col sm:flex-row gap-3 mb-3">
        <div className="flex-1">
          <Input
            placeholder="URL da ferramenta (ex: https://zabbix.empresa.com.br)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="bg-secondary border-border text-foreground placeholder:text-muted-foreground focus:border-primary"
          />
        </div>
        <Button
          type="button"
          variant="outline"
          onClick={handleDetect}
          disabled={detecting}
          className="border-primary/30 text-primary hover:bg-primary/10 hover:text-primary"
        >
          {detecting ? (
            <Loader2 className="h-4 w-4 mr-1 animate-spin" />
          ) : (
            <Globe className="h-4 w-4 mr-1" />
          )}
          {detecting ? "Detectando..." : "Detectar Versão"}
        </Button>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1">
          <Input
            placeholder="Nome (ex: gitlab, jenkins, docker)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="bg-secondary border-border text-foreground placeholder:text-muted-foreground focus:border-primary"
            list="tool-suggestions"
          />
          <datalist id="tool-suggestions">
            {AVAILABLE_TOOLS.map(t => (
              <option key={t} value={t} />
            ))}
          </datalist>
        </div>
        <div className="w-full sm:w-40">
          <Input
            placeholder="Versão (ex: 15.3)"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            className="bg-secondary border-border text-foreground placeholder:text-muted-foreground focus:border-primary"
          />
        </div>
        <div className="w-full sm:w-40">
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value as ToolCategory)}
            className="flex h-10 w-full rounded-md border border-border bg-secondary px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none"
          >
            {(Object.entries(CATEGORY_LABELS) as [ToolCategory, string][]).map(([value, label]) => (
              <option key={value} value={value}>{label.slice(0, -1)}</option>
            ))}
          </select>
        </div>
        <Button type="submit" className="bg-primary text-primary-foreground hover:bg-primary/80 glow-primary">
          <Plus className="h-4 w-4 mr-1" />
          Adicionar
        </Button>
      </form>

      <p className="text-xs text-muted-foreground mt-3">
        Ferramentas disponíveis: {AVAILABLE_TOOLS.join(", ")}
      </p>
    </motion.div>
  );
}
