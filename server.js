const express = require("express");
const path    = require("path");

const PORT              = process.env.PORT || 5000;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";

const app = express();

// ─── Static files (only these exact files are served) ────────────────────────
const STATIC = {
  "style.css":   "text/css",
  "favicon.svg": "image/svg+xml",
  "index.html":  "text/html",
};
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/:file", (req, res, next) => {
  const mime = STATIC[req.params.file];
  if (!mime) return next();
  res.type(mime).sendFile(path.join(__dirname, req.params.file));
});

function withTimeout(ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

// ─── Discord REST API using DISCORD_BOT_TOKEN (no bot-hosting URL needed) ────
async function fetchBotStatusFromDiscordApi() {
  const t = withTimeout(4000);
  try {
    const res = await fetch("https://discord.com/api/v10/users/@me/guilds?with_counts=true", {
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
      signal: t.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const guilds = await res.json();
    const guildCount = guilds.length;
    const userCount  = guilds.reduce((sum, g) => sum + (g.approximate_member_count || 0), 0);
    return { reachable: true, online: true, guildCount, userCount, uptimeMs: null };
  } finally {
    t.clear();
  }
}

async function fetchBotStatus() {
  try {
    if (!DISCORD_BOT_TOKEN) throw new Error("Set DISCORD_BOT_TOKEN");
    return await fetchBotStatusFromDiscordApi();
  } catch (err) {
    return { reachable: false, online: false, guildCount: 0, userCount: 0, uptimeMs: 0, error: err.message };
  }
}

// ─── API: status ───────────────────────────────────────────────────────────────
app.get("/api/status", async (_req, res) => {
  res.json(await fetchBotStatus());
});

app.listen(PORT, "0.0.0.0", () => console.log(`[website] Listening on :${PORT}`));

module.exports = app;
