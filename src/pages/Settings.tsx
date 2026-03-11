import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Plus, Trash2, Save, KeyRound, Palette } from "lucide-react";
import { BrandingSettingsSection } from "@/components/BrandingSettings";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { getProviders, saveProvider, deleteProvider } from "@/lib/api-client";
import { useAuth } from "@/hooks/useAuth";
import { toast } from "sonner";
import { motion } from "framer-motion";

interface OidcProvider {
  id?: string;
  name: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  enabled: boolean;
}

const emptyProvider: OidcProvider = {
  name: "keycloak",
  display_name: "Keycloak",
  issuer_url: "",
  client_id: "",
  client_secret: "",
  scopes: "openid profile email",
  enabled: false,
};

const Settings = () => {
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const [providers, setProviders] = useState<OidcProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadProviders();
  }, []);

  async function loadProviders() {
    try {
      const data = await getProviders();
      setProviders(data || []);
    } catch (err) {
      console.error(err);
      toast.error("Erro ao carregar provedores.");
    }
    setLoading(false);
  }

  const addProvider = () => {
    setProviders([...providers, { ...emptyProvider }]);
  };

  const updateProvider = (index: number, field: keyof OidcProvider, value: any) => {
    const updated = [...providers];
    (updated[index] as any)[field] = value;
    setProviders(updated);
  };

  const removeProvider = async (index: number) => {
    const provider = providers[index];
    if (provider.id) {
      try {
        await deleteProvider(provider.id);
      } catch {
        toast.error("Erro ao remover provedor.");
        return;
      }
    }
    setProviders(providers.filter((_, i) => i !== index));
    toast.info("Provedor removido.");
  };

  const saveProviders = async () => {
    setSaving(true);
    try {
      for (const provider of providers) {
        if (!provider.issuer_url || !provider.client_id || !provider.client_secret) {
          toast.error("Preencha todos os campos obrigatórios.");
          setSaving(false);
          return;
        }
        const result = await saveProvider(provider);
        if (!provider.id && result?.id) provider.id = result.id;
      }
      toast.success("Configurações salvas!");
      loadProviders();
    } catch (err: any) {
      console.error(err);
      toast.error("Erro ao salvar configurações.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground">Carregando...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background scanline">
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate("/")}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
            <KeyRound className="h-5 w-5 text-primary text-glow" />
          </div>
          <div>
            <h1 className="text-xl font-sans font-bold text-foreground">Configurações</h1>
            <p className="text-xs text-muted-foreground">Provedores OIDC / Keycloak</p>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 space-y-8 max-w-3xl">
        {/* Branding Section */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <BrandingSettingsSection />
        </motion.div>

        {/* OIDC Section */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-sans font-semibold text-foreground">Provedores OIDC</h2>
            <Button size="sm" onClick={addProvider}>
              <Plus className="h-4 w-4 mr-1" /> Adicionar
            </Button>
          </div>

          {providers.length === 0 ? (
            <div className="bg-card border border-border rounded-lg p-8 text-center">
              <KeyRound className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-muted-foreground text-sm">
                Nenhum provedor OIDC configurado.
              </p>
              <Button size="sm" className="mt-4" onClick={addProvider}>
                <Plus className="h-4 w-4 mr-1" /> Adicionar provedor
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {providers.map((provider, index) => (
                <div key={provider.id || index} className="bg-card border border-border rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-sans font-medium text-foreground">
                      {provider.display_name || "Novo Provedor"}
                    </h3>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        <Label htmlFor={`enabled-${index}`} className="text-xs text-muted-foreground">
                          {provider.enabled ? "Ativo" : "Inativo"}
                        </Label>
                        <Switch
                          id={`enabled-${index}`}
                          checked={provider.enabled}
                          onCheckedChange={(v) => updateProvider(index, "enabled", v)}
                        />
                      </div>
                      <Button variant="ghost" size="icon" onClick={() => removeProvider(index)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Nome de exibição</Label>
                      <Input
                        value={provider.display_name}
                        onChange={(e) => updateProvider(index, "display_name", e.target.value)}
                        placeholder="Keycloak Corporativo"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Identificador</Label>
                      <Input
                        value={provider.name}
                        onChange={(e) => updateProvider(index, "name", e.target.value)}
                        placeholder="keycloak"
                      />
                    </div>
                    <div className="md:col-span-2 space-y-2">
                      <Label>Issuer URL</Label>
                      <Input
                        value={provider.issuer_url}
                        onChange={(e) => updateProvider(index, "issuer_url", e.target.value)}
                        placeholder="https://keycloak.example.com/realms/myrealm"
                      />
                      <p className="text-xs text-muted-foreground">
                        URL base do realm no Keycloak (sem /protocol/openid-connect)
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label>Client ID</Label>
                      <Input
                        value={provider.client_id}
                        onChange={(e) => updateProvider(index, "client_id", e.target.value)}
                        placeholder="secversions-client"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Client Secret</Label>
                      <Input
                        type="password"
                        value={provider.client_secret}
                        onChange={(e) => updateProvider(index, "client_secret", e.target.value)}
                        placeholder="••••••••"
                      />
                    </div>
                    <div className="md:col-span-2 space-y-2">
                      <Label>Scopes</Label>
                      <Input
                        value={provider.scopes}
                        onChange={(e) => updateProvider(index, "scopes", e.target.value)}
                        placeholder="openid profile email"
                      />
                    </div>
                  </div>
                </div>
              ))}

              <Button onClick={saveProviders} disabled={saving} className="w-full">
                <Save className="h-4 w-4 mr-2" />
                {saving ? "Salvando..." : "Salvar configurações"}
              </Button>
            </div>
          )}
        </motion.div>
      </main>
    </div>
  );
};

export default Settings;
