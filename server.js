import express from "express";
import OpenAI from "openai";

const app = express();
app.use(express.json({ limit: "1mb" }));

// Serve o site (frontend) direto do mesmo servidor
app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HVAC AI PRO</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 30px auto; padding: 0 16px; }
    textarea { width: 100%; height: 110px; padding: 10px; }
    button { padding: 10px 14px; margin-top: 10px; cursor: pointer; }
    pre { white-space: pre-wrap; background: #f6f6f6; padding: 12px; border-radius: 8px; }
    .hint { color: #555; font-size: 14px; margin-top: 6px; }
  </style>
</head>
<body>
  <h1>HVAC AI PRO</h1>
  <p class="hint">Diagnóstico + cálculos + boas práticas</p>

  <textarea id="msg" placeholder="Ex: Split R410A gelando pouco, evaporadora congelando..."></textarea>
  <button id="send">Analisar</button>
  <p class="hint" id="status"></p>

  <h3>Resposta</h3>
  <pre id="out"></pre>

  <script>
    const msg = document.getElementById("msg");
    const out = document.getElementById("out");
    const send = document.getElementById("send");
    const statusEl = document.getElementById("status");

    send.addEventListener("click", async () => {
      const text = msg.value.trim();
      if (!text) return;
      statusEl.textContent = "Consultando IA...";
      out.textContent = "";

      try {
        const r = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: text })
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data?.error || "Erro");
        out.textContent = data.text || "";
      } catch (e) {
        out.textContent = "Erro: " + e.message;
      } finally {
        statusEl.textContent = "";
      }
    });
  </script>
</body>
</html>`);
});

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const HVAC_PROMPT = `
Você é uma Inteligência Artificial especializada em HVAC (ar condicionado e refrigeração), atuando como técnico sênior de campo.

Objetivos:
- Diagnosticar falhas em split, VRF/VRV, chillers, geladeiras/freezers e câmaras frias.
- Orientar testes no campo, manutenção preventiva e boas práticas.
- Explicar de forma prática e profissional.

Regras:
- Antes de concluir diagnóstico, faça perguntas essenciais (modelo, gás, pressões sucção/descarga, temperaturas de linha, temperatura ambiente, sintomas, histórico).
- Não invente medições; indique o que precisa ser medido.
- Priorize segurança elétrica e procedimentos.
`;

app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body || {};
    if (!message || typeof message !== "string") {
      return res.status(400).json({ error: "Envie { message: string }" });
    }

    const response = await client.responses.create({
      model: process.env.OPENAI_MODEL || "gpt-5.2",
      instructions: HVAC_PROMPT,
      input: message,
      temperature: 0.3
    });

    res.json({ text: response.output_text || "" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Falha ao chamar a IA. Verifique OPENAI_API_KEY." });
  }
});

// Render usa PORT dinâmico
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Rodando na porta", PORT));
