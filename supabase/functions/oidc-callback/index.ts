import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { code, providerId, redirectUri } = await req.json();

    if (!code || !providerId || !redirectUri) {
      return new Response(
        JSON.stringify({ error: "Missing required parameters" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);

    // Fetch provider config
    const { data: provider, error: providerError } = await supabaseAdmin
      .from("oidc_providers")
      .select("*")
      .eq("id", providerId)
      .eq("enabled", true)
      .single();

    if (providerError || !provider) {
      return new Response(
        JSON.stringify({ error: "Provider not found or disabled" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Exchange code for tokens
    const tokenUrl = `${provider.issuer_url}/protocol/openid-connect/token`;
    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: provider.client_id,
        client_secret: provider.client_secret,
      }),
    });

    if (!tokenRes.ok) {
      console.error("Token exchange failed:", await tokenRes.text());
      return new Response(
        JSON.stringify({ error: "Token exchange failed" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const tokens = await tokenRes.json();

    // Fetch user info
    const userinfoUrl = `${provider.issuer_url}/protocol/openid-connect/userinfo`;
    const userinfoRes = await fetch(userinfoUrl, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (!userinfoRes.ok) {
      return new Response(
        JSON.stringify({ error: "Failed to fetch user info" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const userinfo = await userinfoRes.json();
    const email = userinfo.email;
    const fullName = userinfo.name || userinfo.preferred_username || "";

    if (!email) {
      return new Response(
        JSON.stringify({ error: "Email not provided by OIDC provider" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Check if user exists in Supabase (direct lookup instead of listing all users)
    const { data: profileData } = await supabaseAdmin
      .from("profiles")
      .select("id")
      .eq("email", email)
      .maybeSingle();

    let existingUser: any = null;
    if (profileData) {
      const { data: userData } = await supabaseAdmin.auth.admin.getUserById(profileData.id);
      existingUser = userData?.user || null;
    }

    let userId: string;

    if (existingUser) {
      userId = existingUser.id;
    } else {
      // Create user with a random password (OIDC-only login)
      const randomPassword = crypto.randomUUID() + crypto.randomUUID();
      const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
        email,
        password: randomPassword,
        email_confirm: true,
        user_metadata: { full_name: fullName, oidc_provider: provider.name },
      });

      if (createError || !newUser.user) {
        console.error("Failed to create user:", createError);
        return new Response(
          JSON.stringify({ error: "Failed to create user account" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      userId = newUser.user.id;
    }

    // Generate a session for the user
    const { data: sessionData, error: sessionError } =
      await supabaseAdmin.auth.admin.generateLink({
        type: "magiclink",
        email,
      });

    if (sessionError) {
      console.error("Session generation failed:", sessionError);
      return new Response(
        JSON.stringify({ error: "Failed to generate session" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Use the token hash to verify OTP and get a real session
    const tokenHash = sessionData.properties?.hashed_token;
    
    // We'll return the verification details so the client can complete the flow
    // Actually, let's directly sign in the user using the admin API
    // by generating a magic link token and verifying it server-side
    
    // Alternative approach: use signInWithPassword with a known method
    // Best approach for OIDC: return a custom token pair
    
    // Let's use a different approach - sign in with the admin SDK
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY") || Deno.env.get("SUPABASE_PUBLISHABLE_KEY")!;
    const anonClient = createClient(supabaseUrl, anonKey);
    
    // Verify the OTP from the magic link to get a session
    const { data: verifyData, error: verifyError } = await anonClient.auth.verifyOtp({
      token_hash: tokenHash!,
      type: "magiclink",
    });

    if (verifyError || !verifyData.session) {
      console.error("OTP verification failed:", verifyError);
      return new Response(
        JSON.stringify({ error: "Failed to establish session" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ session: verifyData.session }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("OIDC callback error:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
