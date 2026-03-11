import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, LogIn, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login, getPublicProviders } from "@/lib/api-client";
import { useAuth } from "@/hooks/useAuth";
import { useBranding } from "@/hooks/useBranding";
import { toast } from "sonner";
import { motion } from "framer-motion";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [oidcProviders, setOidcProviders] = useState<any[]>([]);
  const navigate = useNavigate();
  const { user, setAuthData } = useAuth();

  useEffect(() => {
    if (user) navigate("/");
  }, [user, navigate]);

  useEffect(() => {
    getPublicProviders().then(setOidcProviders).catch(() => setOidcProviders([]));
  }, []);

  const handleLocalAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const data = await login(email, password);
      setAuthData(data.user, data.isAdmin);
      toast.success("Login realizado com sucesso!");
      navigate("/");
    } catch (err: any) {
      toast.error(err.message || "Erro na autenticação");
    } finally {
      setLoading(false);
    }
  };

  const handleOidcLogin = (provider: any) => {
    const redirectUri = `${window.location.origin}/auth/callback`;
    const nonce = crypto.randomUUID();
    sessionStorage.setItem("oidc_state", JSON.stringify({ nonce, providerId: provider.id }));
    const params = new URLSearchParams({
      client_id: provider.client_id,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: provider.scopes || "openid profile email",
      state: nonce,
    });
    window.location.href = `${provider.issuer_url}/protocol/openid-connect/auth?${params}`;
  };

  return (
    <div className="min-h-screen bg-background scanline flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="text-center mb-8">
          <div className="inline-flex p-3 rounded-lg bg-primary/10 border border-primary/20 mb-4">
            <ShieldCheck className="h-8 w-8 text-primary text-glow" />
          </div>
          <h1 className="text-2xl font-sans font-bold text-foreground">SecVersions</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Entrar na plataforma
          </p>
        </div>

        <div className="bg-card border border-border rounded-lg p-6 space-y-6">
          <form onSubmit={handleLocalAuth} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">E-mail</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="seu@email.com"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Senha</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                minLength={6}
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Aguarde..." : <><LogIn className="h-4 w-4 mr-2" /> Entrar</>}
            </Button>
          </form>

          {oidcProviders.length > 0 && (
            <>
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-border" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">ou</span>
                </div>
              </div>

              <div className="space-y-2">
                {oidcProviders.map((provider) => (
                  <Button
                    key={provider.id}
                    variant="outline"
                    className="w-full border-primary/30 text-foreground hover:bg-primary/10"
                    onClick={() => handleOidcLogin(provider)}
                  >
                    <KeyRound className="h-4 w-4 mr-2" />
                    Entrar com {provider.display_name}
                  </Button>
                ))}
              </div>
            </>
          )}
        </div>
      </motion.div>
    </div>
  );
};

export default Login;
