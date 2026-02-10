import express from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import OpenAI from "openai";
import Database from "better-sqlite3";

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

/* ================= CONFIG ================= */
const JWT_SECRET = process.env.JWT_SECRET || "troque_essa_chave_em_producao";
const COOKIE_NAME = "hvac_session";
const DAILY_LIMIT = Number(process.env.DAILY_LIMIT || 5);

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ================= BANCO ================= */
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

/* ================= SESSÃO ================= */
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
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function requireAuth(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.status(401).json({ error: "Faça login para continuar." });
  req.user = user;
  next();
}

/* ================= CONTROLE DE USO ================= */
function todayISO() { return new Date().toISOString().slice(0, 10); }

function checkAndIncrementUsage(userId) {
  const date = todayISO();
  const row = db.prepare("SELECT count FROM usage WHERE user_id = ? AND date = ?").get(userId, date);

  if (!row) {
    db.prepare("INSERT INTO usage (user_id, date, count) VALUES (?, ?, ?)").run(userId, date, 1);
    return { allowed: true, remaining: DAILY_LIMIT - 1 };
  }

  if (row.count >= DAILY_LIMIT) return { allowed: false, remaining: 0 };

  db.prepare("UPDATE usage SET count = count + 1 WHERE user_id = ? AND date = ?").run(userId, date);
  return { allowed: true, remaining: DAILY_LIMIT - (row.count + 1) };
}

/* ================= AUTENTICAÇÃO ================= */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Informe email e senha." });

    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)")
      .run(email.toLowerCase(), hash, new Date().toISOString());

    setSession(res, { id: info.lastInsertRowid, email });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Erro ao criar conta." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Login inválido." });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Login inválido." });

  setSession(res, user);
  res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const user = getUserFromReq(req);
  res.json({ user: user ? { email: user.email } : null });
});

/* ================= PROMPT DA IA ================= */
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

/* ================= CHAT PROTEGIDO ================= */
app.post("/api/chat", requireAuth, async (req, res) => {
  const usage = checkAndIncrementUsage(req.user.sub);
  if (!usage.allowed) return res.status(403).json({ error: "Limite diário atingido." });

  try {
    const response = await client.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      instructions: HVAC_PROMPT,
      input: req.body.message
    });

    res.json({ text: response.output_text, remaining: usage.remaining });
  } catch (err) {
    res.status(500).json({ error: "Erro ao chamar IA" });
  }
});

/* ================= SITE ================= */
app.get("/", (_, res) => {
  res.send(`
<!doctype html>
<html>
<head><title>HVAC AI PRO</title></head>
<body>
<h1>HVAC AI PRO</h1>

<h3>Login</h3>
<input id="email" placeholder="email">
<input id="password" type="password" placeholder="senha">
<button onclick="signup()">Criar Conta</button>
<button onclick="login()">Entrar</button>
<button onclick="logout()">Sair</button>

<h3>Chat</h3>
<textarea id="msg"></textarea>
<button onclick="send()">Analisar</button>
<pre id="out"></pre>

<script>
async function signup(){
  await fetch('/api/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})})
}
async function login(){
  await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})})
}
async function logout(){ await fetch('/api/auth/logout',{method:'POST'}) }
async function send(){
  const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg.value})})
  const d=await r.json(); out.textContent=d.text||d.error
}
</script>
</body>
</html>
`);
});

app.listen(process.env.PORT || 3000);
