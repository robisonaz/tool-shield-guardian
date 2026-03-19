import { useNavigate } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { AddToolForm } from "@/components/AddToolForm";
import { Button } from "@/components/ui/button";
import { addTool } from "@/lib/tools-data";
import { toast } from "sonner";
import { motion } from "framer-motion";

const AddTool = () => {
  const navigate = useNavigate();

  const handleAdd = async (name: string, version: string, sourceUrl?: string) => {
    toast.info(`Buscando CVEs para "${name} ${version}" na base NVD/NIST...`);

    try {
      const entry = await addTool(name, version, sourceUrl);

      if (entry.is_outdated === null) {
        toast.warning(`"${name}" não encontrada na base de versões.`);
      } else if (entry.is_outdated) {
        toast.error(`"${name} ${version}" está desatualizada! Última: ${entry.latest_version}`);
      } else {
        toast.success(`"${name} ${version}" está atualizada!`);
      }

      if ((entry as any)._cveRateLimited) {
        toast.warning(`Consulta de CVEs limitada pela API do NVD. Tente rechecar em alguns segundos.`);
      } else if (entry.cves.length > 0) {
        toast.error(`${entry.cves.length} CVE(s) encontrada(s) para ${name} ${version}!`);
      } else {
        toast.success(`Nenhuma CVE encontrada para ${name} ${version}.`);
      }
    } catch (err) {
      console.error("Erro ao cadastrar ferramenta:", err);
      toast.error("Erro ao buscar dados, mas a ferramenta foi salva.");
    }

    navigate("/");
  };

  return (
    <div className="min-h-screen bg-background scanline">
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate("/")}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-xl font-sans font-bold text-foreground">Cadastrar Ferramenta</h1>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 max-w-2xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <AddToolForm onAdd={handleAdd} />
        </motion.div>
      </main>
    </div>
  );
};

export default AddTool;
