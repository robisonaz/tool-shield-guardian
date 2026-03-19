import { Router } from "express";
import { requireAuth, requireAdmin } from "../middleware/auth.js";
import pool from "../config/database.js";

const router = Router();

// Get Znuny settings
router.get("/", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM znuny_settings LIMIT 1");
    if (rows.length === 0) {
      return res.json({ enabled: false, base_url: "", username: "", password: "", queue: "Raw", priority: "3 normal", ticket_type: "Unclassified", customer_user: "" });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error("Get znuny settings error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Update Znuny settings
router.put("/", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { enabled, base_url, username, password, queue, priority, ticket_type, customer_user } = req.body;
    const { rows } = await pool.query("SELECT id FROM znuny_settings LIMIT 1");

    if (rows.length === 0) {
      const { rows: newRows } = await pool.query(
        `INSERT INTO znuny_settings (enabled, base_url, username, password, queue, priority, ticket_type, customer_user) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [enabled, base_url, username, password, queue || "Raw", priority || "3 normal", ticket_type || "Unclassified", customer_user || ""]
      );
      return res.json(newRows[0]);
    }

    const { rows: updated } = await pool.query(
      `UPDATE znuny_settings SET enabled=$1, base_url=$2, username=$3, password=$4, queue=$5, priority=$6, ticket_type=$7, customer_user=$8 WHERE id=$9 RETURNING *`,
      [enabled, base_url, username, password, queue || "Raw", priority || "3 normal", ticket_type || "Unclassified", customer_user || "", rows[0].id]
    );
    res.json(updated[0]);
  } catch (err) {
    console.error("Update znuny settings error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Test connection
router.post("/test", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { base_url, username, password } = req.body;
    if (!base_url || !username || !password) {
      return res.status(400).json({ error: "URL, usuário e senha são obrigatórios" });
    }

    const sessionId = await znunyCreateSession(base_url, username, password);
    if (!sessionId) {
      return res.json({ success: false, message: "Falha na autenticação. Verifique credenciais e URL." });
    }

    res.json({ success: true, message: "Conexão bem-sucedida!" });
  } catch (err: any) {
    console.error("Znuny test error:", err);
    res.json({ success: false, message: err.message || "Erro ao conectar" });
  }
});

// Create ticket (called internally or manually)
router.post("/create-ticket", requireAuth, async (req, res) => {
  try {
    const { toolName, version, cves } = req.body;
    if (!toolName || !cves?.length) {
      return res.status(400).json({ error: "toolName and cves required" });
    }

    const { rows } = await pool.query("SELECT * FROM znuny_settings WHERE enabled = true LIMIT 1");
    if (rows.length === 0) {
      return res.json({ success: false, message: "Integração Znuny não configurada ou desabilitada" });
    }

    const settings = rows[0];
    const result = await createZnunyTicket(settings, toolName, version, cves);
    res.json(result);
  } catch (err: any) {
    console.error("Create Znuny ticket error:", err);
    res.status(500).json({ error: err.message || "Erro interno" });
  }
});

// ── Znuny API helpers ──

async function znunyCreateSession(baseUrl: string, username: string, password: string): Promise<string | null> {
  const url = `${baseUrl.replace(/\/+$/, "")}/nph-genericinterface.pl/Webservice/GenericTicketConnectorREST/Session`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ UserLogin: username, Password: password }),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.SessionID || null;
  } catch (err) {
    console.error("[Znuny] Session error:", err);
    return null;
  }
}

async function createZnunyTicket(
  settings: any,
  toolName: string,
  version: string,
  cves: Array<{ id: string; severity: string; description: string }>
) {
  const baseUrl = settings.base_url.replace(/\/+$/, "");
  const sessionId = await znunyCreateSession(baseUrl, settings.username, settings.password);
  if (!sessionId) {
    return { success: false, message: "Falha na autenticação com Znuny" };
  }

  const criticalCves = cves.filter((c: any) => c.severity === "critical");
  if (criticalCves.length === 0) {
    return { success: false, message: "Nenhuma CVE crítica encontrada" };
  }

  const cveList = criticalCves.map((c: any) => `• ${c.id} (${c.severity}): ${c.description}`).join("\n");

  const title = `[SecVersions] CVE Crítica - ${toolName} ${version}`;
  const body = `Alerta automático do SecVersions\n\nFerramenta: ${toolName}\nVersão: ${version}\nCVEs Críticas encontradas: ${criticalCves.length}\n\n${cveList}\n\nRecomendação: Atualizar ${toolName} para a versão mais recente o mais rápido possível.`;

  const ticketUrl = `${baseUrl}/nph-genericinterface.pl/Webservice/GenericTicketConnectorREST/Ticket`;

  try {
    const resp = await fetch(ticketUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        SessionID: sessionId,
        Ticket: {
          Title: title,
          Queue: settings.queue || "Raw",
          Priority: settings.priority || "3 normal",
          Type: settings.ticket_type || "Unclassified",
          CustomerUser: settings.customer_user || settings.username,
          State: "new",
        },
        Article: {
          CommunicationChannel: "Internal",
          SenderType: "agent",
          Subject: title,
          Body: body,
          ContentType: "text/plain; charset=utf8",
        },
      }),
    });

    const data = await resp.json();
    if (data.TicketID) {
      console.log(`[Znuny] Ticket created: #${data.TicketNumber || data.TicketID}`);
      return { success: true, ticketId: data.TicketID, ticketNumber: data.TicketNumber, message: `Chamado #${data.TicketNumber || data.TicketID} criado com sucesso!` };
    }

    return { success: false, message: data.Error?.ErrorMessage || "Erro ao criar chamado" };
  } catch (err: any) {
    console.error("[Znuny] Ticket creation error:", err);
    return { success: false, message: err.message || "Erro de comunicação com Znuny" };
  }
}

export default router;
