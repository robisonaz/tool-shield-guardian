import { useState, useRef } from "react";
import { Palette, Upload, Save, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { resolveBackendUrl } from "@/lib/api-client";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { saveBranding, uploadLogo } from "@/lib/api-client";
import { useBranding, type BrandingSettings as BrandingType } from "@/hooks/useBranding";
import { toast } from "sonner";

const COLOR_PRESETS = [
  { label: "Verde", primary: "160 100% 45%", accent: "190 90% 50%" },
  { label: "Azul", primary: "210 100% 50%", accent: "230 90% 60%" },
  { label: "Roxo", primary: "270 80% 55%", accent: "290 90% 60%" },
  { label: "Vermelho", primary: "0 80% 55%", accent: "15 90% 55%" },
  { label: "Laranja", primary: "30 100% 50%", accent: "45 100% 55%" },
  { label: "Ciano", primary: "185 100% 45%", accent: "200 90% 50%" },
];

export function BrandingSettingsSection() {
  const { branding, reload } = useBranding();
  const [form, setForm] = useState<BrandingType>(branding);
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [previewLogo, setPreviewLogo] = useState<string | null>(branding.logo_url);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleLogoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      toast.error("Logo deve ter no máximo 2MB.");
      return;
    }

    setUploading(true);
    try {
      const result = await uploadLogo(file);
      setForm({ ...form, logo_url: result.logo_url });
      setPreviewLogo(resolveBackendUrl(result.logo_url));
    } catch (err: any) {
      console.error(err);
      toast.error(err.message || "Erro ao fazer upload do logo.");
    } finally {
      setUploading(false);
    }
  };

  const removeLogo = () => {
    setForm({ ...form, logo_url: null });
    setPreviewLogo(null);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await saveBranding({
        app_name: form.app_name,
        app_subtitle: form.app_subtitle,
        logo_url: form.logo_url,
        primary_color: form.primary_color,
        accent_color: form.accent_color,
      });
      await reload();
      toast.success("Branding salvo com sucesso!");
    } catch (err: any) {
      console.error(err);
      toast.error(err.message || "Erro ao salvar branding.");
    } finally {
      setSaving(false);
    }
  };

  const applyPreset = (preset: typeof COLOR_PRESETS[0]) => {
    setForm({ ...form, primary_color: preset.primary, accent_color: preset.accent });
    document.documentElement.style.setProperty("--primary", preset.primary);
    document.documentElement.style.setProperty("--accent", preset.accent);
    document.documentElement.style.setProperty("--ring", preset.primary);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-4">
        <Palette className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-sans font-semibold text-foreground">Branding</h2>
      </div>

      <div className="bg-card border border-border rounded-lg p-5 space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label>Nome da aplicação</Label>
            <Input
              value={form.app_name}
              onChange={(e) => setForm({ ...form, app_name: e.target.value })}
              placeholder="SecVersions"
            />
          </div>
          <div className="space-y-2">
            <Label>Subtítulo</Label>
            <Input
              value={form.app_subtitle}
              onChange={(e) => setForm({ ...form, app_subtitle: e.target.value })}
              placeholder="Monitoramento de versões..."
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label>Logo</Label>
          <div className="flex items-center gap-4">
            {previewLogo ? (
              <div className="relative">
                <img
                  src={previewLogo}
                  alt="Logo"
                  className="h-12 w-12 object-contain rounded border border-border bg-background p-1"
                />
                <button
                  onClick={removeLogo}
                  className="absolute -top-2 -right-2 bg-destructive text-destructive-foreground rounded-full p-0.5"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ) : (
              <div className="h-12 w-12 rounded border border-dashed border-border flex items-center justify-center text-muted-foreground">
                <Upload className="h-5 w-5" />
              </div>
            )}
            <div>
              <input
                ref={fileRef}
                type="file"
                accept="image/png,image/jpeg,image/svg+xml,image/webp"
                onChange={handleLogoUpload}
                className="hidden"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => fileRef.current?.click()}
                disabled={uploading}
              >
                <Upload className="h-3.5 w-3.5 mr-1.5" />
                {uploading ? "Enviando..." : "Upload logo"}
              </Button>
              <p className="text-xs text-muted-foreground mt-1">PNG, JPG, SVG ou WebP. Máx 2MB.</p>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <Label>Tema de cores</Label>
          <div className="flex flex-wrap gap-2">
            {COLOR_PRESETS.map((preset) => (
              <button
                key={preset.label}
                onClick={() => applyPreset(preset)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
                  form.primary_color === preset.primary
                    ? "border-primary bg-primary/10 text-foreground"
                    : "border-border text-muted-foreground hover:border-primary/50"
                }`}
              >
                <span
                  className="h-3 w-3 rounded-full"
                  style={{ backgroundColor: `hsl(${preset.primary})` }}
                />
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label>Cor primária (HSL)</Label>
            <div className="flex items-center gap-2">
              <span
                className="h-6 w-6 rounded border border-border flex-shrink-0"
                style={{ backgroundColor: `hsl(${form.primary_color})` }}
              />
              <Input
                value={form.primary_color}
                onChange={(e) => setForm({ ...form, primary_color: e.target.value })}
                placeholder="160 100% 45%"
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>Cor de destaque (HSL)</Label>
            <div className="flex items-center gap-2">
              <span
                className="h-6 w-6 rounded border border-border flex-shrink-0"
                style={{ backgroundColor: `hsl(${form.accent_color})` }}
              />
              <Input
                value={form.accent_color}
                onChange={(e) => setForm({ ...form, accent_color: e.target.value })}
                placeholder="190 90% 50%"
              />
            </div>
          </div>
        </div>

        <div className="bg-background border border-border rounded-lg p-4">
          <p className="text-xs text-muted-foreground mb-2">Pré-visualização</p>
          <div className="flex items-center gap-3">
            {previewLogo ? (
              <img src={previewLogo} alt="Preview" className="h-8 w-8 object-contain" />
            ) : (
              <div
                className="h-8 w-8 rounded flex items-center justify-center text-xs font-bold"
                style={{
                  backgroundColor: `hsl(${form.primary_color} / 0.15)`,
                  color: `hsl(${form.primary_color})`,
                  border: `1px solid hsl(${form.primary_color} / 0.3)`,
                }}
              >
                {form.app_name.charAt(0)}
              </div>
            )}
            <div>
              <p className="text-sm font-sans font-bold text-foreground">{form.app_name}</p>
              <p className="text-xs text-muted-foreground">{form.app_subtitle}</p>
            </div>
          </div>
        </div>

        <Button onClick={handleSave} disabled={saving} className="w-full">
          <Save className="h-4 w-4 mr-2" />
          {saving ? "Salvando..." : "Salvar branding"}
        </Button>
      </div>
    </div>
  );
}
