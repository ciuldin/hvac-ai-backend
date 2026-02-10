import express from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import OpenAI from "openai";
import Database from "better-sqlite3";

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// ===== CONFIG =====
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const COOKIE_NAME = "hvac_session";
const DAILY_LIMIT = Number(process.env.DAILY_LIMIT || 5);

// OpenAI
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// DB
const db = new Database("db.sqlite");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS usage (
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (user_id, date)
  );
`);

function setSession(res, user) {
  const token = jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

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
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.status(401).json({ error: "Faça login para continuar." });
  req.user = user;
  next();
}

function todayISO() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

function checkAndIncrementUsage(userId) {
  const date = todayISO();

  const row = db.prepare(
    "SELECT count FROM usage WHERE user_id = ? AND date = ?"
  ).get(userId, date);

  if (!row) {
    db.prepare(
      "INSERT INTO usage (user_id, date, count) VALUES (?, ?, ?)"
    ).run(userId, date, 1);

    return { allowed: true, remaining: Math.max(DAILY_LIMIT - 1, 0) };
  }

  if (row.count >= DAILY_LIMIT) {
    return { allowed: false, remaining: 0 };
  }

  db.prepare(
    "UPDATE usage SET count = count + 1 WHERE user_id = ? AND date = ?"
  ).run(userId, date);

  const newCount = row.count + 1;
  return { allowed: true, remaining: Math.max(DAILY_LIMIT - newCount, 0) };
}

// ===== AUTH =====
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Informe email e senha." });
    if (password.length < 6) return res.status(400).json({ error: "Senha deve ter no mínimo 6 caracteres." });

    const cleanEmail = email.toLowerCase().trim();
    const password_hash = await bcrypt.hash(password, 10);

    const info = db.prepare(
      "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)"
    ).run(cleanEmail, password_hash, new Date().toISOString());

    const user = { id: info.lastInsertRowid, email: cleanEmail };
    setSession(res, user);

    res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ error: "Este email já está cadastrado." });
    console.error(e);
    res.status(500).json({ error: "Erro ao criar conta." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Informe email e senha." });

    const cleanEmail = email.toLowerCase().trim();
    const row = db.prepare(
      "SELECT id, email, password_hash FROM users WHERE email = ?"
    ).get(cleanEmail);

    if (!row) return res.status(401).json({ error: "Email ou senha inválidos." });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: "Email ou senha inválidos." });

    setSession(res, { id: row.id, email: row.email });
    res.json({ ok: true, user: { id: row.id, email: row.email } });
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
  const user = getUserFromReq(req);
  if (!user) return res.json({ user: null });
  res.json({ user: { email: user.email } });
});

// ===== SITE =====
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
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 30px auto; padding: 0 16px; }
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
  <p class="hint">Login + limite grátis diário (${DAILY_LIMIT}/dia)</p>

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

    <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap;">
      <button id="signup">Criar conta</button>
      <button id="login">Entrar</button>
      <button id="logout" style="display:none;">Sair</button>
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

  async function refreshMe(){
    const r = await fetch("/api/auth/me");
    const data = await r.json();
    if (data.user?.email){
      meEl.innerHTML = "<b>Logado como:</b> " + data.user.email;
      logoutBtn.style.display = "inline-block";
    } else {
      meEl.innerHTML = "<b>Você não está logado.</b>";
      logoutBtn.style.display = "none";
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

      $("out").textContent = data.text + "\\n\\nPerguntas restantes hoje: " + data.remaining;

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

// ===== CHAT (PROTEGIDO + LIMITE) =====
const HVAC_PROMPT = `
Você é uma IA especialista em HVAC/refrigeração (técnico sênior).
Sempre faça perguntas essenciais antes de concluir diagnóstico (modelo, gás, pressões, temperaturas, ambiente, sintomas).
Não invente medições. Priorize segurança.
`;

app.post("/api/chat", requireAuth, async (req, res) => {
  try {
    const usage = checkAndIncrementUsage(req.user.sub);

    if (!usage.allowed) {
      return res.status(403).json({
        error: "Limite grátis diário atingido. Volte amanhã ou assine o plano profissional."
      });
    }

    const { message } = req.body || {};
    if (!message || typeof message !== "string") {
      return res.status(400).json({ error: "Envie { message: string }" });
    }

    const response = await client.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      instructions: HVAC_PROMPT,
      input: message,
      temperature: 0.3
    });

    res.json({ text: response.output_text || "", remaining: usage.remaining });
  } catch (err) {
    console.error("OPENAI ERROR:", err?.status, err?.message);
    res.status(500).json({ error: `${err?.status || ""} ${err?.message || "Falha ao chamar IA"}` });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Rodando na porta", PORT));
