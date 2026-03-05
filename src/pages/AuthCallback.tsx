import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { Loader2 } from "lucide-react";

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get("code");
    const state = searchParams.get("state"); // provider id

    if (!code || !state) {
      setError("Parâmetros de autenticação inválidos.");
      return;
    }

    handleCallback(code, state);
  }, [searchParams]);

  async function handleCallback(code: string, providerId: string) {
    try {
      const { data, error } = await supabase.functions.invoke("oidc-callback", {
        body: { code, providerId, redirectUri: `${window.location.origin}/auth/callback` },
      });

      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      if (data?.session) {
        await supabase.auth.setSession({
          access_token: data.session.access_token,
          refresh_token: data.session.refresh_token,
        });
        toast.success("Login realizado com sucesso!");
        navigate("/");
      } else {
        throw new Error("Sessão não retornada");
      }
    } catch (err: any) {
      console.error("OIDC callback error:", err);
      setError(err.message || "Falha na autenticação OIDC");
      toast.error("Falha na autenticação OIDC");
    }
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-4">
          <p className="text-destructive font-medium">{error}</p>
          <button onClick={() => navigate("/login")} className="text-primary hover:underline text-sm">
            Voltar ao login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center space-y-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
        <p className="text-muted-foreground text-sm">Autenticando...</p>
      </div>
    </div>
  );
};

export default AuthCallback;
