import { useState } from "react";
import { Plus, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AVAILABLE_TOOLS } from "@/lib/tools-data";
import { motion } from "framer-motion";

interface AddToolFormProps {
  onAdd: (name: string, version: string) => void;
}

export function AddToolForm({ onAdd }: AddToolFormProps) {
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !version.trim()) return;
    onAdd(name.trim(), version.trim());
    setName("");
    setVersion("");
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
