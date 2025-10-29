Collector Bot - README
======================

Files:
- bot.js              : main Node.js collector + Telegram bot
- package.json        : dependencies and start script
- utils/encryption.js : helper (optional use)
- .env.example        : sample env variables
- tokens.db           : created at runtime

Quick deploy (Render)
1. Create a GitHub repo and push these files.
2. In Render, create a Web Service -> connect repo.
3. Build Command: npm install
4. Start Command: npm start
5. Add Environment Variables in Render (copy from .env.example and fill real values)
   - BOT_TOKEN, WEBHOOK_URL, ADMIN_CHAT_ID, FORWARDER_SECRET, DASHBOARD_PASSWORD, ENCRYPTION_KEY
6. Deploy. Check logs for:
   - "✅ DB initialized."
   - "✅ Webhook set to: https://your-app-name.onrender.com/tg/<BOT_TOKEN>"
   - "🌐 Collector listening on :10000"

Test:
- Send /help or /count from your admin Telegram account to the bot.
- Use your forwarder to POST to /ingest with header X-FORWARDER-SECRET and JSON {"payload":"...","note":"..."}.

Security:
- Keep ENCRYPTION_KEY secret.
- Do not commit .env with real keys.
- Only use for your own data; do not collect others' credentials.

