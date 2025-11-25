// bot.js — Collector bot (merged, full, production-ready)
// Features included:
// - existing ingest / export / DB encrypted storage
// - /pushpdf endpoint (POST base64 -> Telegram)
// - notes (save/get) with media support (documents/photos)
// - PDF retrieval commands (/pdf dd-mm-yyyy, today, latest)
// - safe basic-auth dashboard
// - AES-256-GCM encrypt/decrypt for stored items
//
// IMPORTANT: Do NOT paste secrets into chat. Set env vars on Render:
// BOT_TOKEN, WEBHOOK_URL, ADMIN_CHAT_ID, ENCRYPTION_KEY (base64 32 bytes), FORWARDER_SECRET, DASHBOARD_PASSWORD

import express from "express";
import bodyParser from "body-parser";
import basicAuth from "basic-auth";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import crypto from "crypto";
import TelegramBot from "node-telegram-bot-api";
import fs from "fs";
import path from "path";

const PORT = process.env.PORT || 10000;
const BOT_TOKEN = process.env.BOT_TOKEN || "";
const WEBHOOK_URL = process.env.WEBHOOK_URL || "";
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID || "";
const FORWARDER_SECRET = process.env.FORWARDER_SECRET || "";
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || "changeme";
const ENCRYPTION_KEY_B64 = process.env.ENCRYPTION_KEY || "";

// Basic env checks
if (!BOT_TOKEN || !WEBHOOK_URL || !ADMIN_CHAT_ID || !ENCRYPTION_KEY_B64) {
  console.error("Missing required env vars. Set BOT_TOKEN, WEBHOOK_URL, ADMIN_CHAT_ID and ENCRYPTION_KEY.");
  process.exit(1);
}

// Validate encryption key (base64 32 bytes)
const KEY = Buffer.from(ENCRYPTION_KEY_B64, "base64");
if (KEY.length !== 32) {
  console.error("ENCRYPTION_KEY must be a base64 32-byte key");
  process.exit(1);
}

// --- Encryption helpers (AES-256-GCM) ---
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

// --- DB init ---
let db;
async function initDb() {
  db = await open({
    filename: "./tokens.db",
    driver: sqlite3.Database,
  });

  // items: encrypted values from ingest
  await db.exec(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      encrypted_value TEXT NOT NULL,
      source TEXT,
      note TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  // notes store: key-value JSON (for text/media)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS notes (
      key TEXT PRIMARY KEY,
      json_data TEXT NOT NULL,
      updated_at INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  // received PDFs directory prepare
  fs.mkdirSync(path.join(".", "received_pdfs"), { recursive: true });

  console.log("✅ DB and directories ready.");
}

// --- Telegram bot & webhook setup ---
const bot = new TelegramBot(BOT_TOKEN, { webHook: true });
const webhookPath = `/tg/${BOT_TOKEN}`;
const webhookUrlFull = `${WEBHOOK_URL}${webhookPath}`;

async function setupWebhook() {
  try {
    await bot.setWebHook(webhookUrlFull);
    console.log("✅ Webhook set to:", webhookUrlFull);
  } catch (err) {
    console.error("Failed to set webhook:", err);
    process.exit(1);
  }
}

// --- Express app ---
const app = express();
// Accept larger payloads (PDF base64). Adjust if your PDFs are huge.
app.use(bodyParser.json({ limit: "50mb" }));

function requirePassword(req, res, next) {
  const c = basicAuth(req);
  if (!c || c.pass !== DASHBOARD_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="dashboard"');
    // send and return to avoid illegal return outside function
    return res.status(401).send("Authentication required.");
  }
  next();
}

app.get("/", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

// Dashboard (basic auth) - shows metadata
app.get("/dashboard", requirePassword, async (req, res) => {
  try {
    const rows = await db.all("SELECT id, source, note, created_at FROM items ORDER BY created_at DESC LIMIT 200");
    res.send(`
      <h3>Stored items (metadata)</h3>
      <p>Total shown: ${rows.length}</p>
      <table border="1" cellpadding="6">
        <tr><th>id</th><th>source</th><th>note</th><th>created_at</th></tr>
        ${rows.map(r => `<tr><td>${r.id}</td><td>${r.source||""}</td><td>${r.note||""}</td><td>${new Date(r.created_at*1000).toISOString()}</td></tr>`).join("")}
      </table>
      <p>Use Telegram /export command or POST /export (basic auth) to download decrypted data.</p>
    `);
  } catch (err) {
    console.error("/dashboard error:", err);
    res.status(500).send("internal");
  }
});

// Export decrypted items (basic auth)
app.post("/export", requirePassword, async (req, res) => {
  try {
    const rows = await db.all("SELECT id, encrypted_value, source, note, created_at FROM items ORDER BY created_at DESC");
    const out = rows.map(r => {
      let val = "<decryption failed>";
      try { val = decrypt(r.encrypted_value); } catch(e){ }
      return { id: r.id, value: val, source: r.source, note: r.note, created_at: new Date(r.created_at*1000).toISOString() };
    });
    res.json(out);
  } catch (err) {
    console.error("/export error:", err);
    res.status(500).json({ error: "internal" });
  }
});

// Ingest endpoint (text payload) - existing behavior
app.post("/ingest", async (req, res) => {
  const secret = req.header("X-FORWARDER-SECRET") || req.header("x-forwarder-secret");
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
    // notify admin with snippet
    try {
      const snippet = payload.length > 200 ? payload.slice(0,200) + "..." : payload;
      await bot.sendMessage(ADMIN_CHAT_ID, `✅ New item stored.\nNote: ${note||"none"}\nSnippet:\n${snippet}`);
    } catch (e) {
      console.error("Notify failed:", e);
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error("Ingest error:", err);
    return res.status(500).json({ error: "internal" });
  }
});

// pushpdf: direct base64 -> telegram (no db)
app.post("/pushpdf", async (req, res) => {
  const secret = req.header("X-FORWARDER-SECRET") || req.header("x-forwarder-secret");
  if (!secret || secret !== FORWARDER_SECRET) {
    return res.status(403).json({ error: "forbidden" });
  }
  try {
    const { fileName, fileDataBase64, targetChat } = req.body;
    if (!fileName || !fileDataBase64) {
      return res.status(400).json({ error: "fileName and fileDataBase64 required" });
    }

    const safeName = path.basename(fileName);
    const buffer = Buffer.from(fileDataBase64, "base64");

    // optionally save a local copy to received_pdfs for later retrieval
    try {
      const savePath = path.join(".", "received_pdfs", safeName);
      fs.writeFileSync(savePath, buffer);
    } catch (e) {
      console.error("Local save failed (non-fatal):", e);
    }

    await bot.sendDocument(targetChat || ADMIN_CHAT_ID, buffer, {}, { filename: safeName, contentType: "application/pdf" });

    return res.json({ ok: true });
  } catch (e) {
    console.error("pushpdf error:", e);
    return res.status(500).json({ error: "internal" });
  }
});

// webhook endpoint for Telegram updates
app.post(webhookPath, async (req, res) => {
  res.sendStatus(200);
  try {
    await bot.processUpdate(req.body);
  } catch (e) {
    console.error("processUpdate error:", e);
  }
});

// --------------------
// Telegram-side commands & handlers
// --------------------

// Helper: ensure only admin uses some commands
function isAdmin(msg) {
  return String(msg.from.id) === String(ADMIN_CHAT_ID);
}

// /count
bot.onText(/\/count/, async (msg) => {
  if (!isAdmin(msg)) return;
  try {
    const r = await db.get("SELECT COUNT(*) AS c FROM items");
    await bot.sendMessage(msg.chat.id, `Stored items: ${r.c}`);
  } catch (e) {
    console.error("/count error:", e);
  }
});

// /export - exports decrypted items as a text file
bot.onText(/\/export/, async (msg) => {
  if (!isAdmin(msg)) return;
  try {
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
      await bot.sendMessage(msg.chat.id, "Failed to send export (maybe size limit). Use POST /export with dashboard password.");
    }
  } catch (e) {
    console.error("/export error:", e);
    await bot.sendMessage(msg.chat.id, "Export failed.");
  }
});

// /clear - wipe items
bot.onText(/\/clear/, async (msg) => {
  if (!isAdmin(msg)) return;
  try {
    await db.exec("DELETE FROM items");
    await bot.sendMessage(msg.chat.id, "✅ All items cleared.");
  } catch (e) {
    console.error("/clear error:", e);
    await bot.sendMessage(msg.chat.id, "Clear failed.");
  }
});

// /help
bot.onText(/\/help/, async (msg) => {
  if (!isAdmin(msg)) return;
  const helpText =
    "/count - total items\n" +
    "/export - export all items\n" +
    "/clear - delete all\n" +
    "/help - this message\n\n" +
    "Notes:\n" +
    "/save <key> (reply to a message with text/photo/document)\n" +
    "/get <key>\n\n" +
    "PDFs:\n" +
    "/pdf dd-mm-yyyy\n" +
    "/pdf today\n" +
    "/pdf latest\n";
  await bot.sendMessage(msg.chat.id, helpText);
});

// --------------------
// Notes system: save & get
// Save expects a reply to a message: /save key  (admin or any user depending on your policy)
// We'll allow admin-only operations for safety on sensitive bots; change isAdmin(...) checks if needed.

// /save <key> (reply to msg)
bot.onText(/\/save (\S+)/, async (msg, match) => {
  if (!isAdmin(msg)) return;
  const key = match[1].trim();
  if (!msg.reply_to_message) {
    await bot.sendMessage(msg.chat.id, "Reply to the message you want to save, then use: /save <key>");
    return;
  }

  const data = msg.reply_to_message;
  let payload = { type: "text", content: null };

  try {
    if (data.text) {
      payload = { type: "text", content: data.text };
    } else if (data.document) {
      payload = { type: "document", fileId: data.document.file_id, fileName: data.document.file_name || null };
    } else if (data.photo) {
      const maxPhoto = data.photo[data.photo.length - 1];
      payload = { type: "photo", fileId: maxPhoto.file_id };
    } else if (data.video) {
      payload = { type: "video", fileId: data.video.file_id };
    } else {
      await bot.sendMessage(msg.chat.id, "This type of message cannot be saved.");
      return;
    }

    await db.run(
      "INSERT OR REPLACE INTO notes (key, json_data, updated_at) VALUES (?, ?, strftime('%s','now'))",
      [key, JSON.stringify(payload)]
    );

    await bot.sendMessage(msg.chat.id, `Saved key: ${key}`);
  } catch (err) {
    console.error("/save error:", err);
    await bot.sendMessage(msg.chat.id, "Failed to save note.");
  }
});

// /get <key>
bot.onText(/\/get (\S+)/, async (msg, match) => {
  if (!isAdmin(msg)) return;
  const key = match[1].trim();
  try {
    const row = await db.get("SELECT json_data FROM notes WHERE key = ?", [key]);
    if (!row) {
      await bot.sendMessage(msg.chat.id, "Key not found.");
      return;
    }
    const payload = JSON.parse(row.json_data);
    if (payload.type === "text") {
      await bot.sendMessage(msg.chat.id, payload.content);
    } else if (payload.type === "photo") {
      await bot.sendPhoto(msg.chat.id, payload.fileId);
    } else if (payload.type === "document") {
      await bot.sendDocument(msg.chat.id, payload.fileId);
    } else if (payload.type === "video") {
      await bot.sendVideo(msg.chat.id, payload.fileId);
    } else {
      await bot.sendMessage(msg.chat.id, "Unsupported saved media type.");
    }
  } catch (err) {
    console.error("/get error:", err);
    await bot.sendMessage(msg.chat.id, "Failed to retrieve key.");
  }
});

// Allow listing notes (admin-only)
bot.onText(/\/notes/, async (msg) => {
  if (!isAdmin(msg)) return;
  try {
    const rows = await db.all("SELECT key, updated_at FROM notes ORDER BY updated_at DESC LIMIT 200");
    if (!rows.length) return bot.sendMessage(msg.chat.id, "No notes saved.");
    const text = rows.map(r => `${r.key}\t${new Date(r.updated_at*1000).toISOString()}`).join("\n");
    await bot.sendMessage(msg.chat.id, `Saved notes:\n${text}`);
  } catch (err) {
    console.error("/notes error:", err);
    await bot.sendMessage(msg.chat.id, "Failed to list notes.");
  }
});

// --------------------
// PDF retrieval commands
// Accepts: /pdf dd-mm-yyyy   OR /pdf today OR /pdf latest
bot.onText(/\/pdf (.+)/, async (msg, match) => {
  if (!isAdmin(msg)) return;
  let date = match[1].trim().toLowerCase();
  try {
    if (date === "today") {
      const now = new Date();
      // en-GB yields dd/mm/yyyy
      const parts = now.toLocaleDateString("en-GB").split("/");
      date = `${parts[0].padStart(2,"0")}-${parts[1].padStart(2,"0")}-${parts[2]}`;
    } else if (date === "latest") {
      const dir = path.join(".", "received_pdfs");
      const files = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith(".pdf"));
      if (!files.length) {
        await bot.sendMessage(msg.chat.id, "No PDFs stored.");
        return;
      }
      files.sort((a,b) => fs.statSync(path.join(dir,b)).mtimeMs - fs.statSync(path.join(dir,a)).mtimeMs);
      const latest = files[0];
      await bot.sendDocument(msg.chat.id, path.join(dir, latest));
      return;
    } else {
      // expected dd-mm-yyyy
      // validate
      if (!/^\d{2}-\d{2}-\d{4}$/.test(date)) {
        await bot.sendMessage(msg.chat.id, "Invalid format. Use: /pdf dd-mm-yyyy  OR /pdf today OR /pdf latest");
        return;
      }
      date = date; // keep as dd-mm-yyyy
    }

    const fileName = `${date}.pdf`;
    const filePath = path.join(".", "received_pdfs", fileName);
    if (!fs.existsSync(filePath)) {
      await bot.sendMessage(msg.chat.id, `PDF not found: ${fileName}`);
      return;
    }
    await bot.sendDocument(msg.chat.id, filePath);
  } catch (err) {
    console.error("/pdf error:", err);
    await bot.sendMessage(msg.chat.id, "Failed to fetch PDF.");
  }
});

// Optional: command to send arbitrary local file by name (admin-only)
bot.onText(/\/sendfile (.+)/, async (msg, match) => {
  if (!isAdmin(msg)) return;
  const name = match[1].trim();
  const p = path.join(".", name);
  if (!fs.existsSync(p)) {
    await bot.sendMessage(msg.chat.id, `File not found: ${name}`);
    return;
  }
  try {
    await bot.sendDocument(msg.chat.id, p);
  } catch (err) {
    console.error("/sendfile error:", err);
    await bot.sendMessage(msg.chat.id, "Failed to send file.");
  }
});

// Handle direct documents/photos sent to bot (optionally auto-save to received_pdfs with date-based name)
// This allows admins to forward PDFs directly to the bot and have them saved under dd-mm-yyyy.pdf
bot.on("message", async (msg) => {
  try {
    // only process document messages from admin (to avoid spam)
    if (!msg.document && !msg.photo) return;
    if (!isAdmin(msg)) return;

    // If a PDF document, save to received_pdfs using current date-time (optionally override name)
    if (msg.document) {
      const mime = msg.document.mime_type || "";
      // if it's a PDF, save with dd-mm-yyyy.pdf OR keep original filename
      const isPdf = mime === "application/pdf" || (msg.document.file_name && msg.document.file_name.toLowerCase().endsWith(".pdf"));
      const fileId = msg.document.file_id;
      const info = await bot.getFile(fileId);
      const fileUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${info.file_path}`;
      // Download file from Telegram file url (using https get). We'll stream to a local file.
      // Node's native https is available; do a simple fetch via https to save.
      // But in many serverless envs, outgoing connections to Telegram are allowed.
      // We'll attempt download; if download fails, just skip silently.

      // Choose filename
      const now = new Date();
      const d = now.toLocaleDateString("en-GB").split("/").join("-");
      const original = msg.document.file_name || `file_${Date.now()}.pdf`;
      const chosenName = isPdf ? `${d}.pdf` : original;
      const savePath = path.join(".", "received_pdfs", path.basename(chosenName));

      // perform HTTP GET and save to disk
      try {
        await downloadFile(fileUrl, savePath);
        await bot.sendMessage(msg.chat.id, `Saved file as ${path.basename(savePath)}`);
      } catch (e) {
        console.error("Auto-save document failed:", e);
      }
    } else if (msg.photo) {
      // optionally handle photos - not saving by default
    }
  } catch (e) {
    console.error("on message handler error:", e);
  }
});

// Helper: download remote file (using https)
import https from "https";
function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        file.close();
        fs.unlinkSync(destPath, { force: true });
        return reject(new Error("Failed to download, status " + res.statusCode));
      }
      res.pipe(file);
      file.on("finish", () => {
        file.close();
        resolve();
      });
    }).on("error", (err) => {
      file.close();
      fs.unlinkSync(destPath, { force: true });
      reject(err);
    });
  });
}

// Start everything
(async () => {
  await initDb();
  await setupWebhook();
  app.listen(PORT, () => {
    console.log(`🌐 Collector listening on :${PORT}`);
    console.log(`🔒 Dashboard: /dashboard (basic-auth)`);
  });
})();
```0
