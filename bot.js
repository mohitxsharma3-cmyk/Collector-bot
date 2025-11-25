// -------------------------------
// Imports
// -------------------------------
import express from "express";
import bodyParser from "body-parser";
import basicAuth from "basic-auth";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import TelegramBot from "node-telegram-bot-api";
import crypto from "crypto";
import multer from "multer";
import fs from "fs";
import path from "path";

// -------------------------------
// ENV SETUP
// -------------------------------
const PORT = process.env.PORT || 10000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const WEBHOOK_URL = process.env.WEBHOOK_URL;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || "changeme";
const FORWARDER_SECRET = process.env.FORWARDER_SECRET || "secret123";
const ENCRYPTION_KEY_B64 = process.env.ENCRYPTION_KEY;

if (!BOT_TOKEN || !WEBHOOK_URL || !ADMIN_CHAT_ID || !ENCRYPTION_KEY_B64) {
  console.error("❌ Missing required env variables.");
  process.exit(1);
}

// -------------------------------
// Encryption Key (AES-256-GCM)
// -------------------------------
const KEY = Buffer.from(ENCRYPTION_KEY_B64, "base64");
if (KEY.length !== 32) {
  console.error("❌ ENCRYPTION_KEY must be 32 bytes in base64 format.");
  process.exit(1);
}

// AES encryption
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64");
}

// AES decryption
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
// -------------------------------
// PART 2/6
// DB init, Telegram setup, Express app, multer, basic helpers
// Paste this right after Part 1
// -------------------------------

/* DB initialization and tables */
let db;
async function initDb() {
  db = await open({
    filename: "./collector.db",
    driver: sqlite3.Database,
  });

  // items: encrypted ingest
  await db.exec(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      encrypted_value TEXT NOT NULL,
      source TEXT,
      note TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  // simple key-value text notes (Rose-like)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS notes (
      key TEXT PRIMARY KEY,
      json_data TEXT NOT NULL,
      updated_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  // file_notes: store Telegram file_id references + metadata
  await db.exec(`
    CREATE TABLE IF NOT EXISTS file_notes (
      key TEXT PRIMARY KEY,
      file_id TEXT NOT NULL,
      file_name TEXT,
      file_type TEXT,
      updated_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  // ensure directory for stored files
  fs.mkdirSync(path.join(".", "received_files"), { recursive: true });

  console.log("✅ DB tables ready and received_files directory ensured.");
}

/* Telegram bot & webhook */
const bot = new TelegramBot(BOT_TOKEN, { webHook: true });
const webhookPath = `/tg/${BOT_TOKEN}`;
const webhookUrlFull = `${WEBHOOK_URL}${webhookPath}`;

async function setupWebhook() {
  try {
    await bot.setWebHook(webhookUrlFull);
    console.log("✅ Webhook set:", webhookUrlFull);
  } catch (err) {
    console.error("Failed to set webhook:", err);
    process.exit(1);
  }
}

/* Express app + body parsing + multer for multipart uploads */
const app = express();
// JSON bodies for API calls (large payloads allowed, but we'll prefer multipart)
app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "100mb" }));

// multer in-memory storage (we write to disk explicitly later)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });

/* Basic auth wrapper for dashboard routes */
function requirePassword(req, res, next) {
  const c = basicAuth(req);
  if (!c || c.pass !== DASHBOARD_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="dashboard"');
    return res.status(401).send("Authentication required.");
  }
  next();
}

/* Simple root health-check */
app.get("/", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});
// -------------------------------
// PART 3/6
// Collector ingest, dropfile (file upload), pushfile (raw base64 optional),
// webhook handler
// -------------------------------

/* INGEST: encrypted text storage */
app.post("/ingest", async (req, res) => {
  try {
    const secret = req.header("X-FORWARDER-SECRET");
    if (secret !== FORWARDER_SECRET)
      return res.status(403).json({ error: "forbidden" });

    const { payload, note } = req.body;
    if (!payload) return res.status(400).json({ error: "payload missing" });

    const enc = encrypt(payload);

    await db.run(
      "INSERT INTO items (encrypted_value, source, note) VALUES (?, ?, ?)",
      [enc, req.ip, note || null]
    );

    // Notify on Telegram
    const snippet = payload.length > 200 ? payload.slice(0, 200) + "..." : payload;
    await bot.sendMessage(
      ADMIN_CHAT_ID,
      `📥 New Item Stored\nNote: ${note || "-"}\n${snippet}`
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("INGEST error:", err);
    res.status(500).json({ error: "internal" });
  }
});

/* DROPFILE: Best system — file upload via multipart/form-data
   Use-this → ChatGPT can directly upload a PDF/Excel/Image without base64 */
app.post("/dropfile", upload.single("file"), async (req, res) => {
  try {
    const secret = req.header("X-FORWARDER-SECRET");
    if (secret !== FORWARDER_SECRET)
      return res.status(403).json({ error: "forbidden" });

    if (!req.file)
      return res.status(400).json({ error: "no file uploaded" });

    // Telegram target
    const targetChat = req.body.targetChat || ADMIN_CHAT_ID;

    const safeName = Date.now() + "_" + req.file.originalname;
    const filePath = path.join("received_files", safeName);

    fs.writeFileSync(filePath, req.file.buffer);

    // Forward to Telegram
    await bot.sendDocument(
      targetChat,
      req.file.buffer,
      {},
      { filename: safeName }
    );

    res.json({ ok: true, file: safeName });
  } catch (err) {
    console.error("dropfile error:", err);
    res.status(500).json({ error: "internal" });
  }
});

/* OPTIONAL PUSHFILE (if you ever want base64 style)
   - keep it here, no harm, but dropfile is main
*/
app.post("/pushfile", async (req, res) => {
  try {
    const secret = req.header("X-FORWARDER-SECRET");
    if (secret !== FORWARDER_SECRET)
      return res.status(403).json({ error: "forbidden" });

    const { fileName, fileDataBase64, targetChat } = req.body;
    if (!fileName || !fileDataBase64)
      return res.status(400).json({ error: "file required" });

    const buffer = Buffer.from(fileDataBase64, "base64");
    const safeName = Date.now() + "_" + path.basename(fileName);
    const filePath = path.join("received_files", safeName);

    fs.writeFileSync(filePath, buffer);

    await bot.sendDocument(
      targetChat || ADMIN_CHAT_ID,
      buffer,
      {},
      { filename: safeName }
    );

    res.json({ ok: true, file: safeName });
  } catch (err) {
    console.error("pushfile error:", err);
    res.status(500).json({ error: "internal" });
  }
});

/* TELEGRAM WEBHOOK HANDLER */
app.post(`/tg/${BOT_TOKEN}`, (req, res) => {
  res.sendStatus(200);
  try {
    bot.processUpdate(req.body);
  } catch (err) {
    console.error("Webhook process error:", err);
  }
});
// -------------------------------
// PART 4/6
// TEXT NOTES SYSTEM (Ross-Bot Style)
// save / get / notes / del
// -------------------------------

// Save a text note using: /save key   (must reply to a text message)
bot.onText(/\/save (\S+)/, async (msg, match) => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const key = match[1];
    const reply = msg.reply_to_message;

    if (!reply || !reply.text)
      return bot.sendMessage(msg.chat.id, "Reply to a text message to save.");

    const payload = {
      type: "text",
      content: reply.text,
    };

    await db.run(
      "INSERT OR REPLACE INTO notes (key, json_data, updated_at) VALUES (?, ?, strftime('%s','now'))",
      [key, JSON.stringify(payload)]
    );

    bot.sendMessage(msg.chat.id, `Saved text note under key: ${key}`);
  } catch (err) {
    bot.sendMessage(msg.chat.id, "Error saving note.");
  }
});

// Get note: /get key
bot.onText(/\/get (\S+)/, async (msg, match) => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const key = match[1];
    const row = await db.get("SELECT * FROM notes WHERE key = ?", [key]);

    if (!row) return bot.sendMessage(msg.chat.id, "No note with that key.");

    const data = JSON.parse(row.json_data);
    if (data.type === "text") {
      return bot.sendMessage(msg.chat.id, data.content);
    }

    bot.sendMessage(msg.chat.id, "Note exists, but not text type.");
  } catch (err) {
    bot.sendMessage(msg.chat.id, "Error reading note.");
  }
});

// List all text note keys
bot.onText(/\/notes/, async msg => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const rows = await db.all("SELECT key, updated_at FROM notes ORDER BY updated_at DESC");

    if (!rows.length) return bot.sendMessage(msg.chat.id, "No notes saved.");

    let out = rows
      .map(r => `${r.key}  |  ${new Date(r.updated_at * 1000).toLocaleString()}`)
      .join("\n");

    bot.sendMessage(msg.chat.id, out);
  } catch (err) {
    bot.sendMessage(msg.chat.id, "Error listing notes.");
  }
});

// Delete a text note: /del key
bot.onText(/\/del (\S+)/, async (msg, match) => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const key = match[1];
    await db.run("DELETE FROM notes WHERE key = ?", [key]);

    bot.sendMessage(msg.chat.id, `Deleted note: ${key}`);
  } catch (err) {
    bot.sendMessage(msg.chat.id, "Error deleting note.");
  }
});
// -------------------------------
// PART 5/6
// FILE NOTES SYSTEM (Ross-Bot Style)
// savefile / getfile / filekeys / delfile
// -------------------------------

// /savefile key  (must reply to a document or photo)
bot.onText(/\/savefile (\S+)/, async (msg, match) => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const key = match[1];
    const reply = msg.reply_to_message;

    if (!reply)
      return bot.sendMessage(msg.chat.id, "Reply to a file or photo to save.");

    let fileId = null;
    let fileName = null;
    let fileType = null;

    // Document handling
    if (reply.document) {
      fileId = reply.document.file_id;
      fileName = reply.document.file_name || "document";
      fileType = reply.document.mime_type || "document";
    }

    // Photo handling
    else if (reply.photo) {
      const p = reply.photo[reply.photo.length - 1];
      fileId = p.file_id;
      fileName = "photo.jpg";
      fileType = "photo";
    }

    else {
      return bot.sendMessage(msg.chat.id, "This reply has no file.");
    }

    await db.run(
      "INSERT OR REPLACE INTO file_notes (key, file_id, file_name, file_type, updated_at) VALUES (?, ?, ?, ?, strftime('%s','now'))",
      [key, fileId, fileName, fileType]
    );

    bot.sendMessage(msg.chat.id, `Saved file under key: ${key}`);
  } catch (err) {
    console.error("savefile error:", err);
    bot.sendMessage(msg.chat.id, "Error saving file.");
  }
});

// /getfile key  → send saved file
bot.onText(/\/getfile (\S+)/, async (msg, match) => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const key = match[1];
    const row = await db.get("SELECT * FROM file_notes WHERE key = ?", [key]);

    if (!row)
      return bot.sendMessage(msg.chat.id, "No file saved for this key.");

    if (row.file_type === "photo") {
      return bot.sendPhoto(msg.chat.id, row.file_id);
    }

    await bot.sendDocument(
      msg.chat.id,
      row.file_id,
      {},
      { filename: row.file_name || "file" }
    );
  } catch (err) {
    console.error("getfile error:", err);
    bot.sendMessage(msg.chat.id, "Error sending file.");
  }
});

// /filekeys  → list all saved file keys
bot.onText(/\/filekeys/, async msg => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const rows = await db.all("SELECT key, updated_at FROM file_notes ORDER BY updated_at DESC");

    if (!rows.length)
      return bot.sendMessage(msg.chat.id, "No saved files.");

    let out = rows
      .map(r => `${r.key}  |  ${new Date(r.updated_at * 1000).toLocaleString()}`)
      .join("\n");

    bot.sendMessage(msg.chat.id, out);
  } catch (err) {
    console.error("filekeys err:", err);
    bot.sendMessage(msg.chat.id, "Error listing file keys.");
  }
});

// /delfile key  → delete saved file key
bot.onText(/\/delfile (\S+)/, async (msg, match) => {
  try {
    if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

    const key = match[1];
    await db.run("DELETE FROM file_notes WHERE key = ?", [key]);

    bot.sendMessage(msg.chat.id, `Deleted saved file: ${key}`);
  } catch (err) {
    console.error("delfile err:", err);
    bot.sendMessage(msg.chat.id, "Error deleting file note.");
  }
});
// -------------------------------
// PART 6/6
// Commands list, sendlatestfile, count/export/clear,
// server startup block
// -------------------------------

// List all available commands
bot.onText(/\/help/, msg => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

  const helpText = `
📌 Available Commands:

📍 Text Notes (Ross Style)
  /save <key>   (reply to text)
  /get <key>
  /notes
  /del <key>

📍 File Notes (Ross Style)
  /savefile <key>   (reply to file/photo)
  /getfile <key>
  /filekeys
  /delfile <key>

📍 Collector & Files
  /sendlatestfile
  /count
  /export
  /clear
  `;

  bot.sendMessage(msg.chat.id, helpText);
});

// Count collector items
bot.onText(/\/count/, async msg => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

  const r = await db.get("SELECT COUNT(*) AS c FROM items");
  bot.sendMessage(msg.chat.id, `Stored items: ${r.c}`);
});

// Export collector items
bot.onText(/\/export/, async msg => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

  const rows = await db.all("SELECT * FROM items ORDER BY created_at DESC");
  const out = rows
    .map(r => {
      let val = "<decrypt error>";
      try { val = decrypt(r.encrypted_value); } catch {}
      return `${r.id}\t${r.source || ""}\t${r.note || ""}\t${new Date(
        r.created_at * 1000
      ).toISOString()}\t${val}`;
    })
    .join("\n");

  bot.sendDocument(
    msg.chat.id,
    Buffer.from(out, "utf8"),
    {},
    { filename: "export.txt", contentType: "text/plain" }
  );
});

// Clear collector table
bot.onText(/\/clear/, async msg => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;
  await db.exec("DELETE FROM items");
  bot.sendMessage(msg.chat.id, "Collector items cleared.");
});

// Send latest uploaded file
bot.onText(/\/sendlatestfile/, async msg => {
  if (String(msg.from.id) !== String(ADMIN_CHAT_ID)) return;

  const dir = "./received_files";
  if (!fs.existsSync(dir)) return bot.sendMessage(msg.chat.id, "No files folder found.");

  const list = fs.readdirSync(dir);
  if (!list.length) return bot.sendMessage(msg.chat.id, "No files stored yet.");

  const latest = list.sort().reverse()[0];
  const buffer = fs.readFileSync(path.join(dir, latest));

  await bot.sendDocument(
    msg.chat.id,
    buffer,
    {},
    { filename: latest }
  );
});

// --------------------------------
// START SERVER + WEBHOOK
// --------------------------------
(async () => {
  try {
    await initDb();
    await setupWebhook();
    app.listen(PORT, () => {
      console.log(`🚀 Collector Bot running on port ${PORT}`);
      console.log(`Webhook: ${webhookUrlFull}`);
    });
  } catch (err) {
    console.error("Startup error:", err);
  }
})();
