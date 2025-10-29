// collector/bot.js
import express from "express";
import bodyParser from "body-parser";
import basicAuth from "basic-auth";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import crypto from "crypto";
import TelegramBot from "node-telegram-bot-api";

const PORT = process.env.PORT || 10000;
const BOT_TOKEN = process.env.BOT_TOKEN; // required
const WEBHOOK_URL = process.env.WEBHOOK_URL; // required e.g. https://your-app.onrender.com
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID; // required (your numeric chat id)
const FORWARDER_SECRET = process.env.FORWARDER_SECRET; // required secret that forwarder sends in header
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || "change_me";
const ENCRYPTION_KEY_B64 = process.env.ENCRYPTION_KEY; // base64 32 bytes required

if (!BOT_TOKEN || !WEBHOOK_URL || !ADMIN_CHAT_ID || !FORWARDER_SECRET || !ENCRYPTION_KEY_B64) {
  console.error("Missing required env vars. Set BOT_TOKEN, WEBHOOK_URL, ADMIN_CHAT_ID, FORWARDER_SECRET, ENCRYPTION_KEY.");
  process.exit(1);
}

const KEY = Buffer.from(ENCRYPTION_KEY_B64, "base64");
if (KEY.length !== 32) {
  console.error("ENCRYPTION_KEY must be 32 bytes (base64).");
  process.exit(1);
}

// AES-256-GCM helpers
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64");
}
function decrypt(b64) {
  const data = Buffer.from(b64, "base64");
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const ct = data.slice(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plain.toString("utf8");
}

let db;
async function initDb() {
  db = await open({
    filename: "./items.db",
    driver: sqlite3.Database,
  });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      encrypted_value TEXT NOT NULL,
      source TEXT,
      note TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `);
  console.log("✅ DB initialized.");
}

const bot = new TelegramBot(BOT_TOKEN, { webHook: true });
const webhookPath = `/tg/${BOT_TOKEN}`; // endpoint Telegram will POST updates to
const webhookUrlFull = `${WEBHOOK_URL}${webhookPath}`;

// set webhook on startup
async function setupWebhook() {
  try {
    await bot.setWebHook(webhookUrlFull);
    console.log("✅ Webhook set to:", webhookUrlFull);
  } catch (err) {
    console.error("Failed to set webhook:", err);
    process.exit(1);
  }
}

const app = express();
app.use(bodyParser.json({ limit: "200kb" }));

// simple basic-auth middleware for dashboard
function requirePassword(req, res, next) {
  const c = basicAuth(req);
  if (!c || c.pass !== DASHBOARD_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="dashboard"');
    return res.status(401).send("Authentication required.");
  }
  next();
}

// Health endpoint
app.get("/", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

// Dashboard (metadata only)
app.get("/dashboard", requirePassword, async (req, res) => {
  const rows = await db.all("SELECT id, source, note, created_at FROM items ORDER BY created_at DESC LIMIT 200");
  res.send(`
    <h3>Stored items (metadata)</h3>
    <p>Total shown: ${rows.length}</p>
    <table border="1" cellpadding="6">
      <tr><th>id</th><th>source</th><th>note</th><th>created_at</th></tr>
      ${rows.map(r => `<tr><td>${r.id}</td><td>${r.source||""}</td><td>${r.note||""}</td><td>${new Date(r.created_at*1000).toISOString()}</td></tr>`).join("")}
    </table>
    <p>Use /export in Telegram (admin) or POST /export to download full decrypted content (basic auth).</p>
  `);
});

// Export full decrypted items (POST)
app.post("/export", requirePassword, async (req, res) => {
  const rows = await db.all("SELECT id, encrypted_value, source, note, created_at FROM items ORDER BY created_at DESC");
  const out = rows.map(r => {
    let val = "<decryption failed>";
    try { val = decrypt(r.encrypted_value); } catch(e){ }
    return { id: r.id, value: val, source: r.source, note: r.note, created_at: new Date(r.created_at*1000).toISOString() };
  });
  res.json(out);
});

// Ingest endpoint for your forwarder
app.post("/ingest", async (req, res) => {
  // simple header-based secret
  const secret = req.header("X-FORWARDER-SECRET");
  if (!secret || secret !== FORWARDER_SECRET) {
    return res.status(403).json({ error: "forbidden" });
  }
  const { payload, note } = req.body;
  if (!payload || typeof payload !== "string") {
    return res.status(400).json({ error: "payload required" });
  }

  try {
    const enc = encrypt(payload);
    await db.run("INSERT INTO items (encrypted_value, source, note) VALUES (?, ?, ?)", [enc, req.ip || null, note || null]);

    // notify admin via Telegram
    try {
      const snippet = payload.length > 200 ? payload.slice(0, 200) + "..." : payload;
      await bot.sendMessage(ADMIN_CHAT_ID, `✅ Ingested payload from forwarder.\nNote: ${note||"none"}\nSnippet:\n${snippet}`);
    } catch (e) {
      console.error("Failed to notify admin:", e);
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("Ingest error:", err);
    return res.status(500).json({ error: "internal" });
  }
});

// Telegram webhook receiver (so bot receives admin commands)
app.post(webhookPath, async (req, res) => {
  // give Telegram immediate response
  res.sendStatus(200);
  try {
    // pass update to node-telegram-bot-api
    bot.processUpdate(req.body);
  } catch (e) {
    console.error("processUpdate error:", e);
  }
});

// Admin Telegram commands: /count, /export, /help
bot.onText(/\/count/, async (msg) => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;
  const r = await db.get("SELECT COUNT(*) AS c FROM items");
  await bot.sendMessage(msg.chat.id, `Stored items: ${r.c}`);
});
bot.onText(/\/export/, async (msg) => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;
  const rows = await db.all("SELECT id, encrypted_value, source, note, created_at FROM items ORDER BY created_at DESC");
  const lines = rows.map(r => {
    let plain = "<decryption failed>";
    try { plain = decrypt(r.encrypted_value); } catch(e){}
    return `${r.id}\t${r.source||""}\t${r.note||""}\t${new Date(r.created_at*1000).toISOString()}\t${plain}`;
  });
  const content = lines.join("\n");
  try {
    await bot.sendDocument(msg.chat.id, Buffer.from(content, "utf8"), {}, { filename: "export.txt", contentType: "text/plain" });
  } catch (e) {
    console.error("sendDocument failed:", e);
    await bot.sendMessage(msg.chat.id, "Failed to send export (maybe size limit). Use /count or POST /export with dashboard password.");
  }
});
bot.onText(/\/help/, async (msg) => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;
  await bot.sendMessage(msg.chat.id, "/count - total items\n/export - export all items (file)\n/help - this message");
});

// Start server and setup webhook
(async () => {
  await initDb();
  await setupWebhook();
  app.listen(PORT, () => {
    console.log(`🌐 Collector listening on :${PORT}`);
    console.log(`🔒 Dashboard: /dashboard (basic-auth)`);
  });
})();
