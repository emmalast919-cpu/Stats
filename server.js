require("dotenv").config();
const express = require("express");
const path    = require("path");
const crypto  = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 5000;

// ─── Discord OAuth + bot config (all secrets come from env vars) ─────────────
// Works with Replit Secrets AND plain .env files (for hosts like bot-hosting.net
// that don't have a "Secrets" tab — just drop a .env file with the same keys).
const DISCORD_CLIENT_ID     = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN     = process.env.DISCORD_BOT_TOKEN;
const DATABASE_URL          = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL;
const SESSION_SECRET        = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const ENC_KEY               = crypto.createHash("sha256").update(SESSION_SECRET).digest();

const MANAGE_GUILD  = 0x20;
const ADMINISTRATOR = 0x8;

// Must match EXACTLY what is registered in the Discord Developer Portal (OAuth2 → Redirects).
function getRedirectUri(req) {
  if (process.env.DISCORD_REDIRECT_URI) return process.env.DISCORD_REDIRECT_URI;
  if (process.env.REPLIT_DEV_DOMAIN) return `https://${process.env.REPLIT_DEV_DOMAIN}/`;
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  return `${proto}://${req.get("host")}/`;
}

const app = express();
app.set("trust proxy", true);
app.use(express.json());

// ─── Database (shared with the bot — guild settings + warnings) ──────────────
const pool = new Pool({ connectionString: DATABASE_URL });

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guild_settings (
      guild_id TEXT PRIMARY KEY,
      log_channel_id TEXT,
      mod_log_channel_id TEXT,
      member_log_channel_id TEXT,
      voice_log_channel_id TEXT,
      server_log_channel_id TEXT,
      log_messages BOOLEAN NOT NULL DEFAULT true,
      log_members BOOLEAN NOT NULL DEFAULT true,
      log_moderation BOOLEAN NOT NULL DEFAULT true,
      log_voice BOOLEAN NOT NULL DEFAULT true,
      log_server BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS voice_log_channel_id TEXT;`);
  await pool.query(`ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS server_log_channel_id TEXT;`);
  await pool.query(`ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS log_voice BOOLEAN NOT NULL DEFAULT true;`);
  await pool.query(`ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS log_server BOOLEAN NOT NULL DEFAULT true;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS warnings (
      id SERIAL PRIMARY KEY,
      guild_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      moderator_id TEXT NOT NULL,
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}
ensureTables().catch((err) => console.error("[db] Failed to set up tables:", err.message));

// ─── Static files (only these exact files are served) ────────────────────────
const STATIC = {
  "style.css":   "text/css",
  "favicon.svg": "image/svg+xml",
  "index.html":  "text/html",
};
app.get("/", async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect("/?login=denied");
  if (!code) return res.sendFile(path.join(__dirname, "index.html"));
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    return res.status(500).send("Login is not configured: missing Discord client credentials.");
  }

  try {
    const redirectUri = getRedirectUri(req);
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
      }),
    });
    if (!tokenRes.ok) throw new Error(`Token exchange failed: ${tokenRes.status}`);
    const tokenData = await tokenRes.json();

    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userRes.ok) throw new Error(`Failed to fetch user: ${userRes.status}`);
    const user = await userRes.json();

    setSessionCookie(res, {
      id: user.id,
      username: user.username,
      avatar: user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
        : `https://cdn.discordapp.com/embed/avatars/${Number(user.discriminator || 0) % 5}.png`,
      accessToken: tokenData.access_token,
    });
    res.redirect("/");
  } catch (err) {
    console.error("[oauth] Login failed:", err.message);
    res.redirect("/?login=failed");
  }
});

// ─── Encrypted session cookie (AES-256-GCM: confidentiality + integrity) ─────
function encryptSession(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, data]).toString("base64url");
}

function decryptSession(token) {
  if (!token) return null;
  try {
    const buf = Buffer.from(token, "base64url");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const data = buf.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const out = Buffer.concat([decipher.update(data), decipher.final()]);
    return JSON.parse(out.toString("utf8"));
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function setSessionCookie(res, payload) {
  const token = encryptSession(payload);
  res.setHeader(
    "Set-Cookie",
    `session=${token}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax${process.env.NODE_ENV === "production" ? "; Secure" : ""}`
  );
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
}

function requireSession(req, res, next) {
  const session = decryptSession(getCookie(req, "session"));
  if (!session) return res.status(401).json({ error: "Not logged in" });
  req.session = session;
  next();
}

// ─── Discord OAuth login flow ──────────────────────────────────────────────────
app.get("/login", (req, res) => {
  if (!DISCORD_CLIENT_ID) {
    return res.status(500).send("Login is not configured: missing DISCORD_CLIENT_ID.");
  }
  const redirectUri = getRedirectUri(req);
  const url = new URL("https://discord.com/api/oauth2/authorize");
  url.searchParams.set("client_id", DISCORD_CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "identify guilds");
  res.redirect(url.toString());
});

app.get("/logout", (_req, res) => {
  clearSessionCookie(res);
  res.redirect("/");
});

// ─── API: current logged-in user (for the dashboard) ──────────────────────────
app.get("/api/me", (req, res) => {
  const session = decryptSession(getCookie(req, "session"));
  if (!session) return res.status(401).json({ loggedIn: false });
  res.json({ loggedIn: true, id: session.id, username: session.username, avatar: session.avatar });
});

// ─── API: live bot status (proxies the bot process's internal /status) ───────
const BOT_STATUS_URL = process.env.BOT_STATUS_URL || `http://127.0.0.1:${process.env.STATUS_PORT || 3001}/status`;
app.get("/api/bot/status", async (_req, res) => {
  try {
    const r = await fetch(BOT_STATUS_URL, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) throw new Error(`status ${r.status}`);
    res.json(await r.json());
  } catch (err) {
    res.json({ online: false, guildCount: 0, userCount: 0, uptimeMs: 0 });
  }
});

// ─── Discord REST helpers (bot token) ─────────────────────────────────────────
async function botFetch(endpoint) {
  const res = await fetch(`https://discord.com/api${endpoint}`, {
    headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
  });
  if (!res.ok) throw new Error(`Discord API ${endpoint} failed: ${res.status}`);
  return res.json();
}

async function canManageGuild(req, guildId) {
  const userGuildsRes = await fetch("https://discord.com/api/users/@me/guilds", {
    headers: { Authorization: `Bearer ${req.session.accessToken}` },
  });
  if (!userGuildsRes.ok) throw new Error("Failed to fetch your servers");
  const userGuilds = await userGuildsRes.json();
  const guild = userGuilds.find((g) => g.id === guildId);
  if (!guild) return false;
  const perms = BigInt(guild.permissions);
  return (perms & BigInt(MANAGE_GUILD)) !== 0n || (perms & BigInt(ADMINISTRATOR)) !== 0n || guild.owner;
}

// ─── API: guilds the logged-in user can manage AND the bot is in ─────────────
app.get("/api/guilds", requireSession, async (req, res) => {
  try {
    const [userGuildsRes, botGuilds] = await Promise.all([
      fetch("https://discord.com/api/users/@me/guilds", {
        headers: { Authorization: `Bearer ${req.session.accessToken}` },
      }),
      botFetch("/users/@me/guilds"),
    ]);
    if (!userGuildsRes.ok) throw new Error("Failed to fetch your servers");
    const userGuilds = await userGuildsRes.json();
    const botGuildIds = new Set(botGuilds.map((g) => g.id));

    const manageable = userGuilds
      .filter((g) => {
        const perms = BigInt(g.permissions);
        return (perms & BigInt(MANAGE_GUILD)) !== 0n || (perms & BigInt(ADMINISTRATOR)) !== 0n || g.owner;
      })
      .map((g) => ({
        id: g.id,
        name: g.name,
        icon: g.icon ? `https://cdn.discordapp.com/icons/${g.id}/${g.icon}.png` : null,
        botInGuild: botGuildIds.has(g.id),
      }));

    res.json(manageable);
  } catch (err) {
    console.error("[api] /api/guilds failed:", err.message);
    res.status(500).json({ error: "Failed to load servers" });
  }
});

// ─── API: guild info (for the dashboard server card) ──────────────────────────
app.get("/api/guild/:id/info", requireSession, async (req, res) => {
  const guildId = req.params.id;
  try {
    if (!(await canManageGuild(req, guildId))) return res.status(403).json({ error: "Not authorized for this server" });
    const guild = await botFetch(`/guilds/${guildId}?with_counts=true`);
    res.json({
      id: guild.id,
      name: guild.name,
      icon: guild.icon ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png` : null,
      memberCount: guild.approximate_member_count ?? null,
      onlineCount: guild.approximate_presence_count ?? null,
    });
  } catch (err) {
    console.error("[api] guild info failed:", err.message);
    res.status(500).json({ error: "Failed to load server info" });
  }
});

// ─── API: guild settings (get channel list + current settings) ───────────────
app.get("/api/guild/:id/settings", requireSession, async (req, res) => {
  const guildId = req.params.id;
  try {
    if (!(await canManageGuild(req, guildId))) return res.status(403).json({ error: "Not authorized for this server" });

    const [channels, { rows }] = await Promise.all([
      botFetch(`/guilds/${guildId}/channels`),
      pool.query("SELECT * FROM guild_settings WHERE guild_id = $1", [guildId]),
    ]);

    const textChannels = channels
      .filter((c) => c.type === 0) // GUILD_TEXT
      .map((c) => ({ id: c.id, name: c.name }));

    const settings = rows[0] || {
      guild_id: guildId,
      log_channel_id: null,
      mod_log_channel_id: null,
      member_log_channel_id: null,
      voice_log_channel_id: null,
      server_log_channel_id: null,
      log_messages: true,
      log_members: true,
      log_moderation: true,
      log_voice: true,
      log_server: true,
    };

    res.json({ channels: textChannels, settings });
  } catch (err) {
    console.error("[api] guild settings failed:", err.message);
    res.status(500).json({ error: "Failed to load server settings" });
  }
});

app.post("/api/guild/:id/settings", requireSession, async (req, res) => {
  const guildId = req.params.id;
  try {
    if (!(await canManageGuild(req, guildId))) return res.status(403).json({ error: "Not authorized for this server" });

    const {
      log_channel_id, mod_log_channel_id, member_log_channel_id, voice_log_channel_id, server_log_channel_id,
      log_messages, log_members, log_moderation, log_voice, log_server,
    } = req.body;
    await pool.query(
      `INSERT INTO guild_settings (
         guild_id, log_channel_id, mod_log_channel_id, member_log_channel_id, voice_log_channel_id, server_log_channel_id,
         log_messages, log_members, log_moderation, log_voice, log_server, updated_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now())
       ON CONFLICT (guild_id) DO UPDATE SET
         log_channel_id = EXCLUDED.log_channel_id,
         mod_log_channel_id = EXCLUDED.mod_log_channel_id,
         member_log_channel_id = EXCLUDED.member_log_channel_id,
         voice_log_channel_id = EXCLUDED.voice_log_channel_id,
         server_log_channel_id = EXCLUDED.server_log_channel_id,
         log_messages = EXCLUDED.log_messages,
         log_members = EXCLUDED.log_members,
         log_moderation = EXCLUDED.log_moderation,
         log_voice = EXCLUDED.log_voice,
         log_server = EXCLUDED.log_server,
         updated_at = now()`,
      [
        guildId,
        log_channel_id || null,
        mod_log_channel_id || null,
        member_log_channel_id || null,
        voice_log_channel_id || null,
        server_log_channel_id || null,
        Boolean(log_messages),
        Boolean(log_members),
        Boolean(log_moderation),
        Boolean(log_voice),
        Boolean(log_server),
      ]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("[api] save guild settings failed:", err.message);
    res.status(500).json({ error: "Failed to save server settings" });
  }
});

// ─── API: recent warnings for a guild ─────────────────────────────────────────
app.get("/api/guild/:id/warnings", requireSession, async (req, res) => {
  const guildId = req.params.id;
  try {
    if (!(await canManageGuild(req, guildId))) return res.status(403).json({ error: "Not authorized for this server" });
    const { rows } = await pool.query(
      "SELECT id, user_id, moderator_id, reason, created_at FROM warnings WHERE guild_id = $1 ORDER BY created_at DESC LIMIT 50",
      [guildId]
    );
    res.json(rows);
  } catch (err) {
    console.error("[api] warnings failed:", err.message);
    res.status(500).json({ error: "Failed to load warnings" });
  }
});

app.delete("/api/guild/:id/warnings/:warningId", requireSession, async (req, res) => {
  const { id: guildId, warningId } = req.params;
  try {
    if (!(await canManageGuild(req, guildId))) return res.status(403).json({ error: "Not authorized for this server" });
    await pool.query("DELETE FROM warnings WHERE id = $1 AND guild_id = $2", [warningId, guildId]);
    res.json({ ok: true });
  } catch (err) {
    console.error("[api] delete warning failed:", err.message);
    res.status(500).json({ error: "Failed to delete warning" });
  }
});

// ─── Remaining static files (kept last so /login, /callback etc. take priority) ─
app.get("/:file", (req, res, next) => {
  const mime = STATIC[req.params.file];
  if (!mime) return next();
  res.type(mime).sendFile(path.join(__dirname, req.params.file));
});

app.listen(PORT, "0.0.0.0", () => console.log(`[website] Listening on :${PORT}`));

module.exports = app;
        
