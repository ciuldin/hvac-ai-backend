import express from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import OpenAI from "openai";
import Database from "better-sqlite3";
import Stripe from "stripe";

const app = express();

/* ================= STRIPE WEBHOOK (precisa vir ANTES do express.json) ================= */
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");

app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET || ""
      );
    } catch (err) {
      console.error("Webhook signature error:", err?.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const userId = session?.metadata?.user_id;

        if (userId) {
          db.prepare("UPDATE users SET plan = 'pro' WHERE id = ?").run(Number(userId));
          // opcional: guardar ids stripe
          if (session.customer) {
            db.prepare("UPDATE users SET stripe_customer_id = ? WHERE id = ?")
              .run(String(session.customer), Number(userId));
          }
          if (session.subscription) {
            db.prepare("UPDATE users SET stripe_subscription_id = ? WHERE id = ?")
              .run(String(session.subscription), Number(userId));
          }
          console.log("User upgraded to PRO:", userId);
        }
      }

      // (Opcional) rebaixar quando cancelar:
      if (event.type === "customer.subscription.deleted") {
        const sub = event.data.object;
        const subId = sub?.id;
        if (subId) {
          db.prepare("UPDATE users SET plan = 'free' WHERE stripe_subscription_id = ?")
            .run(String(subId));
          console.log("User downgraded to FREE (subscription deleted):", subId);
        }
      }

      return res.json({ received: true });
    } catch (e) {
      console.error("Webhook handling error:", e);
      return res.status(500).json({ error: "Webhook handler failed" });
    }
  }
);

/* ================= MIDDLEWARE NORMAL ================= */
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

/* ================= CONFIG ================= */
const JWT_SECRET = process.env.JWT_SECRET || "troque_essa_chave_em_producao";
const COOKIE_NAME = "hvac_session";
const DAILY_LIMIT = Number(process.env.DAILY_LIMIT || 5);
const BASE_URL = process.env.BASE_URL || ""; // ex: https://hvac-ai-backend-icoc.onrender.com

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ================= DB ================= */
const db = new Database("db.sqlite");

// tabela users (com plano)
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    plan TEXT DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT
  );

  CREATE TABLE IF NOT EXISTS usage (
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (user_id, date)
  );
`);

// migração “segura” caso seu users antigo não tenha colunas novas
function tryAlter(sql) {
  try { db.exec(sql); } catch (_) {}
}
tryAlter(`ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'`);
tryAlter(`ALTER TABLE users ADD COLUMN stripe_customer_id TEXT`);
tryAlter(`ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT`);

/* ================= AUTH HELPERS ================= */
function setSession(res, user) {
  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function getUserFromReq(req) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function requireAuth(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.status(401).json({ error: "Faça login para continuar." });
  req.user = user;
  next();
}

/* ================= USAGE LIMIT ================= */
function todayISO() { return new Date().toISOString().slice(0, 10); }

function checkAndIncrementUsage(userId) {
  const date = todayISO();
  const row = db.prepare("SELECT count FROM usage WHERE user_id = ? AND date = ?").get(userId, date);

  if (!row) {
    db.prepare("INSERT INTO usage (user_id, date, count) VALUES (?, ?, ?)").run(userId, date, 1);
    return { allowed: true, remaining: Math.max(DAILY_LIMIT - 1, 0) };
  }

  if (row.count >= DAILY_LIMIT) return { allowed: false, remaining: 0 };

  db.prepare("UPDATE usage SET count = count + 1 WHERE user_id = ? AND date = ?").run(userId, date);
  const newCount = row.count + 1;
  return { allowed: true, remaining: Math.max(DAILY_LIMIT - newCount, 0) };
}

/* ================= AUTH ROUTES ================= */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Informe email e senha." });
    if (String(password).length < 6) return res.status(400).json({ error: "Senha mínimo 6 caracteres." });

    const cleanEmail = String(email).toLowerCase().trim();
    const hash = await bcrypt.hash(String(password), 10);

    const info = db.prepare(
      "INSERT INTO users (email, password_hash, created_at, plan) VALUES (?, ?, ?, 'free')"
    ).run(cleanEmail, hash, new Date().toISOString());

    setSession(res, { id: info.lastInsertRowid, email: cleanEmail });
    res.json({ ok: true });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ error: "Email já cadastrado." });
    console.error(e);
    res.status(500).json({ error: "Erro ao criar conta." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Informe email e senha." });

    const cleanEmail = String(email).toLowerCase().trim();
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(cleanEmail);
    if (!user) return res.status(401).json({ error: "Login inválido." });

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ error: "Login inválido." });

    setSession(res, { id: user.id, email: user.email });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao fazer login." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const session = getUserFromReq(req);
  if (!session) return res.json({ user: null });

  const row = db.prepare("SELECT email, plan FROM users WHERE id = ?").get(session.sub);
  res.json({ user: row ? { email: row.email, plan: row.plan } : { email: session.email, plan: "free" } });
});

/* ================= STRIPE CHECKOUT (ASSINATURA) ================= */
app.post("/api/create-checkout-session", requireAuth, async (req, res) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY) return res.status(500).json({ error: "Stripe não configurado (STRIPE_SECRET_KEY)." });
    if (!process.env.STRIPE_PRICE_ID) return res.status(500).json({ error: "Stripe não configurado (STRIPE_PRICE_ID)." });
    if (!BASE_URL) return res.status(500).json({ error: "BASE_URL não configurado." });

    const userRow = db.prepare("SELECT id, email, plan FROM users WHERE id = ?").get(req.user.sub);
    if (!userRow) return res.status(404).json({ error: "Usuário não encontrado." });

    if (userRow.plan === "pro") {
      return res.json({ url: `${BASE_URL}/?already_pro=true` });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${BASE_URL}/?success=true`,
      cancel_url: `${BASE_URL}/?canceled=true`,
      customer_email: userRow.email,
      metadata: { user_id: String(userRow.id) }
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Falha ao criar checkout." });
  }
});

/* ================= PROMPT IA (OBJETIVO) ================= */
const HVAC_PROMPT = `
Você é uma IA especialista em HVAC/refrigeração (técnico sênior). Seja OBJETIVO.

Regra principal:
- Sempre entregue uma solução imediata primeiro.
- Faça perguntas SOMENTE se forem absolutamente necessárias.
- Se perguntar, faça NO MÁXIMO 1 pergunta. (Nunca mais que 1.)

Padrão de resposta:
1) Diagnóstico provável (1 frase).
2) O que fazer agora (3 passos curtos).
3) (Opcional) 1 pergunta para confirmar, apenas se necessário.

Diretriz:
- Para problemas simples, NÃO pergunte nada: responda direto.
- Não invente medições. Avise risco elétrico/pressão só quando relevante.
`;

/* ================= CHAT (FREE limitado / PRO ilimitado) ================= */
app.post("/api/chat", requireAuth, async (req, res) => {
  try {
    const row = db.prepare("SELECT plan FROM users WHERE id = ?").get(req.user.sub);
    const plan = row?.plan || "free";

    let remaining = "∞";

    if (plan !== "pro") {
      const usage = checkAndIncrementUsage(req.user.sub);
      if (!usage.allowed) {
        return res.status(403).json({ error: "Limite grátis diário atingido. Assine o plano PRO para uso ilimitado." });
      }
      remaining = usage.remaining;
    }

    const { message } = req.body || {};
    if (!message || typeof message !== "string") return res.status(400).json({ error: "Envie { message: string }" });

    const response = await client.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      instructions: HVAC_PROMPT,
      input: message,
      temperature: 0.3
    });

    res.json({ text: response.output_text || "", remaining, plan });
  } catch (err) {
    console.error("OPENAI ERROR:", err?.status, err?.message);
    res.status(500).json({ error: `${err?.status || ""} ${err?.message || "Falha ao chamar IA"}` });
  }
});

/* ================= SITE (login + botão assinar + chat) ================= */
app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HVAC AI PRO</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 920px; margin: 30px auto; padding: 0 16px; }
    textarea { width: 100%; height: 110px; padding: 10px; }
    input { padding: 10px; width: 100%; box-sizing: border-box; }
    button { padding: 10px 14px; cursor: pointer; }
    pre { white-space: pre-wrap; background: #f6f6f6; padding: 12px; border-radius: 8px; }
    .hint { color: #555; font-size: 14px; }
    .card { border: 1px solid #eee; border-radius: 10px; padding: 14px; margin-bottom: 14px; }
    .row { display: grid; gap: 10px; grid-template-columns: 1fr 1fr; }
    @media (max-width: 720px){ .row { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>HVAC AI PRO</h1>
  <p class="hint">FREE: ${DAILY_LIMIT}/dia • PRO: ilimitado</p>

  <div class="card">
    <div id="me"></div>

    <div class="row" style="margin-top:10px;">
      <div>
        <label>Email</label>
        <input id="email" placeholder="seuemail@exemplo.com"/>
      </div>
      <div>
        <label>Senha</label>
        <input id="password" type="password" placeholder="mín. 6 caracteres"/>
      </div>
    </div>

    <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
      <button id="signup">Criar conta</button>
      <button id="login">Entrar</button>
      <button id="logout" style="display:none;">Sair</button>
      <button id="subscribe" style="display:none;">Assinar PRO (ilimitado)</button>
      <span class="hint" id="authStatus"></span>
    </div>
  </div>

  <div class="card">
    <textarea id="msg" placeholder="Descreva o problema do sistema..."></textarea>
    <div style="margin-top:10px; display:flex; gap:10px; align-items:center;">
      <button id="send">Analisar</button>
      <span class="hint" id="status"></span>
    </div>
    <h3>Resposta</h3>
    <pre id="out"></pre>
  </div>

<script>
  const $ = (id)=>document.getElementById(id);
  const authStatus = $("authStatus");
  const statusEl = $("status");
  const meEl = $("me");
  const logoutBtn = $("logout");
  const subscribeBtn = $("subscribe");

  async function refreshMe(){
    const r = await fetch("/api/auth/me");
    const data = await r.json();
    if (data.user?.email){
      meEl.innerHTML = "<b>Logado como:</b> " + data.user.email + " • <b>Plano:</b> " + (data.user.plan || "free");
      logoutBtn.style.display = "inline-block";
      subscribeBtn.style.display = (data.user.plan === "pro") ? "none" : "inline-block";
    } else {
      meEl.innerHTML = "<b>Você não está logado.</b>";
      logoutBtn.style.display = "none";
      subscribeBtn.style.display = "none";
    }
  }

  $("signup").onclick = async ()=>{
    authStatus.textContent = "Criando conta...";
    try{
      const r = await fetch("/api/auth/signup", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ email: $("email").value, password: $("password").value })
      });
      const data = await r.json();
      if(!r.ok) throw new Error(data.error || "Erro");
      authStatus.textContent = "Conta criada ✅";
      await refreshMe();
    }catch(e){ authStatus.textContent = e.message; }
  };

  $("login").onclick = async ()=>{
    authStatus.textContent = "Entrando...";
    try{
      const r = await fetch("/api/auth/login", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ email: $("email").value, password: $("password").value })
      });
      const data = await r.json();
      if(!r.ok) throw new Error(data.error || "Erro");
      authStatus.textContent = "Logado ✅";
      await refreshMe();
    }catch(e){ authStatus.textContent = e.message; }
  };

  $("logout").onclick = async ()=>{
    await fetch("/api/auth/logout", { method:"POST" });
    authStatus.textContent = "Saiu.";
    await refreshMe();
  };

  $("subscribe").onclick = async ()=>{
    authStatus.textContent = "Abrindo pagamento...";
    try{
      const r = await fetch("/api/create-checkout-session", { method:"POST" });
      const data = await r.json();
      if(!r.ok) throw new Error(data.error || "Erro");
      window.location = data.url;
    }catch(e){
      authStatus.textContent = e.message;
    }
  };

  $("send").onclick = async ()=>{
    const text = $("msg").value.trim();
    if(!text) return;
    statusEl.textContent = "Consultando IA...";
    $("out").textContent = "";

    try{
      const r = await fetch("/api/chat", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ message: text })
      });
      const data = await r.json();

      if(!r.ok) throw new Error(data.error || "Erro");

      $("out").textContent =
        data.text + "\\n\\nPlano: " + data.plan + " | Restantes hoje: " + data.remaining;

    }catch(e){
      $("out").textContent = "Erro: " + e.message;
    }finally{
      statusEl.textContent = "";
    }
  };

  refreshMe();
</script>
</body>
</html>
  `);
});

/* ================= START ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Rodando na porta", PORT));
