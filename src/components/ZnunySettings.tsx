import { useState, useEffect } from "react";
import { Ticket, TestTube, Save, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { getZnunySettings, saveZnunySettings, testZnunyConnection, type ZnunySettings } from "@/lib/api-client";
import { toast } from "sonner";

const defaultSettings: ZnunySettings = {
  enabled: false,
  base_url: "",
  username: "",
  password: "",
  queue: "Raw",
  priority: "3 normal",
  ticket_type: "Unclassified",
  customer_user: "",
};

export function ZnunySettingsSection() {
  const [settings, setSettings] = useState<ZnunySettings>(defaultSettings);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    try {
      const data = await getZnunySettings();
      setSettings(data);
    } catch (err) {
      console.error("Failed to load Znuny settings:", err);
    }
  }

  const handleSave = async () => {
    setSaving(true);
    try {
      await saveZnunySettings(settings);
      toast.success("Configurações do Znuny salvas!");
    } catch (err) {
      console.error(err);
      toast.error("Erro ao salvar configurações do Znuny.");
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    if (!settings.base_url || !settings.username || !settings.password) {
      toast.error("Preencha URL, usuário e senha para testar.");
      return;
    }
    setTesting(true);
    try {
      const result = await testZnunyConnection({
        base_url: settings.base_url,
        username: settings.username,
        password: settings.password,
      });
      if (result.success) {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch (err: any) {
      toast.error(err.message || "Erro ao testar conexão");
    } finally {
      setTesting(false);
    }
  };

  const update = (field: keyof ZnunySettings, value: any) => {
    setSettings((prev) => ({ ...prev, [field]: value }));
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Ticket className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-sans font-semibold text-foreground">Integração Znuny / OTRS</h2>
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor="znuny-enabled" className="text-xs text-muted-foreground">
            {settings.enabled ? "Ativo" : "Inativo"}
          </Label>
          <Switch
            id="znuny-enabled"
            checked={settings.enabled}
            onCheckedChange={(v) => update("enabled", v)}
          />
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-5 space-y-4">
        <p className="text-sm text-muted-foreground">
          Quando ativo, um chamado será aberto automaticamente no Znuny/OTRS sempre que uma CVE <strong className="text-destructive">crítica</strong> for detectada ao cadastrar ou rechecar ferramentas.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="md:col-span-2 space-y-2">
            <Label>URL Base do Znuny</Label>
            <Input
              value={settings.base_url}
              onChange={(e) => update("base_url", e.target.value)}
              placeholder="https://znuny.empresa.com/otrs"
            />
            <p className="text-xs text-muted-foreground">
              URL base do Znuny (sem /nph-genericinterface.pl). Ex: https://znuny.empresa.com/otrs
            </p>
          </div>

          <div className="space-y-2">
            <Label>Usuário (Agente)</Label>
            <Input
              value={settings.username}
              onChange={(e) => update("username", e.target.value)}
              placeholder="admin@Admin"
            />
          </div>

          <div className="space-y-2">
            <Label>Senha</Label>
            <Input
              type="password"
              value={settings.password}
              onChange={(e) => update("password", e.target.value)}
              placeholder="••••••••"
            />
          </div>

          <div className="space-y-2">
            <Label>Fila (Queue)</Label>
            <Input
              value={settings.queue}
              onChange={(e) => update("queue", e.target.value)}
              placeholder="Raw"
            />
          </div>

          <div className="space-y-2">
            <Label>Prioridade</Label>
            <Input
              value={settings.priority}
              onChange={(e) => update("priority", e.target.value)}
              placeholder="3 normal"
            />
          </div>

          <div className="space-y-2">
            <Label>Tipo de Ticket</Label>
            <Input
              value={settings.ticket_type}
              onChange={(e) => update("ticket_type", e.target.value)}
              placeholder="Unclassified"
            />
          </div>

          <div className="space-y-2">
            <Label>CustomerUser</Label>
            <Input
              value={settings.customer_user}
              onChange={(e) => update("customer_user", e.target.value)}
              placeholder="cliente@empresa.com"
            />
            <p className="text-xs text-muted-foreground">
              Login do cliente no Znuny. Se vazio, usará o agente.
            </p>
          </div>
        </div>

        <div className="flex gap-2 pt-2">
          <Button onClick={handleTest} variant="outline" disabled={testing} className="border-accent/30 text-accent hover:bg-accent/10">
            {testing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <TestTube className="h-4 w-4 mr-2" />}
            {testing ? "Testando..." : "Testar Conexão"}
          </Button>
          <Button onClick={handleSave} disabled={saving} className="ml-auto">
            {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
            {saving ? "Salvando..." : "Salvar"}
          </Button>
        </div>
      </div>
    </div>
  );
}
