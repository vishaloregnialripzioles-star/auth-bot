require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const {
  ActionRowBuilder, ActivityType, ButtonBuilder, ButtonStyle, Client,
  EmbedBuilder, GatewayIntentBits, REST, Routes, SlashCommandBuilder
} = require("discord.js");

const app = express();
// Render terminates TLS at its proxy; trust one proxy hop for client IP handling.
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https://cdn.discordapp.com https://media.discordapp.net; base-uri 'none'; frame-ancestors 'none'; form-action https://discord.com");
  next();
});

const PORT = Number(process.env.PORT) || 3000;
const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, DATABASE_URL } = process.env;
// Set PUBLIC_URL to the exact public Render service origin (for example, https://auth-bot-xxxx.onrender.com).
// This keeps the Discord button pointed at the deployed website even if REDIRECT_URI is accidentally misconfigured.
const PUBLIC_URL = process.env.PUBLIC_URL;
const STATE_SECRET = process.env.STATE_SECRET || CLIENT_SECRET;
const required = { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, DATABASE_URL };
const missing = Object.keys(required).filter((key) => !required[key]);
if (missing.length) {
  console.error("Missing required environment variables: " + missing.join(", "));
  process.exit(1);
}
let APP_BASE_URL;
try {
  const redirect = new URL(REDIRECT_URI);
  if (redirect.protocol !== "https:" && redirect.hostname !== "localhost") throw new Error("REDIRECT_URI must use HTTPS.");
  if (redirect.pathname !== "/auth/callback") throw new Error("REDIRECT_URI must end with /auth/callback.");
  const publicUrl = new URL(PUBLIC_URL || redirect.origin);
  if (publicUrl.protocol !== "https:" && publicUrl.hostname !== "localhost") throw new Error("PUBLIC_URL must use HTTPS.");
  if (publicUrl.pathname !== "/" || publicUrl.search || publicUrl.hash) throw new Error("PUBLIC_URL must be the website origin only, with no path, query, or fragment.");
  if (publicUrl.origin !== redirect.origin && !PUBLIC_URL) throw new Error("Set PUBLIC_URL to the public website origin.");
  APP_BASE_URL = publicUrl.origin;
} catch (error) {
  console.error("Invalid OAuth URL configuration: " + error.message);
  process.exit(1);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}
function signState(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", STATE_SECRET).update(encoded).digest("base64url");
  return encoded + "." + sig;
}
function verifyState(state) {
  if (typeof state !== "string" || state.length > 2048) return null;
  const parts = state.split(".");
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac("sha256", STATE_SECRET).update(parts[0]).digest();
  const supplied = Buffer.from(parts[1], "base64url");
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!payload || !/^\d{17,20}$/.test(payload.discordId) || !Number.isFinite(payload.exp) || payload.exp < Date.now() || typeof payload.nonce !== "string" || !/^[a-f0-9]{48}$/.test(payload.nonce)) return null;
    return payload;
  } catch { return null; }
}
function cookieSecureAttribute() {
  return new URL(REDIRECT_URI).protocol === "https:" ? "; Secure" : "";
}
function clearCookie(res) {
  res.setHeader("Set-Cookie", "oauth_state=; HttpOnly" + cookieSecureAttribute() + "; SameSite=Lax; Path=/; Max-Age=0");
}
function htmlPage(title, message) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#5865f2"><title>' +
    escapeHtml(title) + ' · Auth Bot</title><style>' +
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top,#252b58 0%,#111322 55%,#0b0c14 100%);color:#f7f7fb;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}.card{width:min(100%,620px);padding:clamp(24px,6vw,48px);border:1px solid #ffffff20;border-radius:28px;background:#171927eF;box-shadow:0 24px 80px #0006}.brand{display:flex;align-items:center;gap:12px;color:#b9bdff;font-size:13px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.mark{display:grid;place-items:center;width:42px;height:42px;border-radius:14px;background:#5865f2;color:white;font-size:22px}.pill{display:inline-flex;align-items:center;gap:8px;margin:28px 0 8px;padding:7px 11px;border:1px solid #7ce6b433;border-radius:999px;background:#7ce6b40d;color:#8ef0c1;font-size:12px;font-weight:700}h1{margin:8px 0 14px;font-size:clamp(28px,6vw,42px);letter-spacing:-.04em;line-height:1.12}p{color:#c5c8d8;line-height:1.75;font-size:16px}.note{margin-top:28px;padding-top:18px;border-top:1px solid #ffffff16;color:#9298b2;font-size:13px}.dot{width:7px;height:7px;border-radius:50%;background:#8ef0c1;box-shadow:0 0 12px #8ef0c1}</style></head><body><main class="card"><div class="brand"><span class="mark">✓</span> AUTH BOT <span style="margin-left:auto;font-size:11px;letter-spacing:0;color:#9298b2">DISCORD OAUTH2</span></div><div class="pill"><span class="dot"></span> Secure authorization</div><h1>' + escapeHtml(title) + '</h1><p>' + message + '</p><div class="note">Official Discord authorization · We never ask for your Discord password.<br>You can close this page and return to Discord.</div></main></body></html>';
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  connectionTimeoutMillis: 10000
});
const dbReady = db.query(`CREATE TABLE IF NOT EXISTS verified_users (
  discord_id VARCHAR(20) PRIMARY KEY,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`).then(() => console.log("Verified-user database ready")).catch(error => {
  console.error("Verified-user database initialization failed: " + error.message);
  process.exit(1);
});
async function isVerified(userId) {
  await dbReady;
  const result = await db.query("SELECT 1 FROM verified_users WHERE discord_id = $1", [userId]);
  return result.rowCount > 0;
}
async function markVerified(userId) {
  await dbReady;
  await db.query("INSERT INTO verified_users (discord_id) VALUES ($1) ON CONFLICT (discord_id) DO NOTHING", [userId]);
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const commandData = [
  new SlashCommandBuilder().setName("ping").setDescription("Check whether the bot is online"),
  new SlashCommandBuilder().setName("help").setDescription("Show available commands"),
  new SlashCommandBuilder().setName("verify").setDescription("Get the authorization button"),
  new SlashCommandBuilder().setName("userinfo").setDescription("Show a user's basic profile")
    .addUserOption(o => o.setName("user").setDescription("User to inspect").setRequired(false)),
  new SlashCommandBuilder().setName("serverinfo").setDescription("Show this server's information"),
  new SlashCommandBuilder().setName("avatar").setDescription("Show a user's avatar")
    .addUserOption(o => o.setName("user").setDescription("User whose avatar to show").setRequired(false)),
  new SlashCommandBuilder().setName("botinfo").setDescription("Show information about this bot"),
  new SlashCommandBuilder().setName("uptime").setDescription("Show bot uptime")
].map(command => command.toJSON());

function verifyRow(userId) {
  const url = new URL("/login", APP_BASE_URL);
  url.searchParams.set("discord_id", userId);
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setLabel("Verify with Discord").setStyle(ButtonStyle.Link).setURL(url.toString())
  );
}
function verifyEmbed() {
  return new EmbedBuilder().setColor(0x5865F2).setTitle("🔒 Authorization required")
    .setDescription("You need to verify your Discord account before using this bot's commands.\n\nPress **Verify with Discord** below and authorize the same account you use in this server. After verification, retry your command.")
    .setFooter({ text: "Secure Discord OAuth2 verification" });
}

async function showVerify(interaction) {
  return interaction.reply({ embeds: [verifyEmbed()], components: [verifyRow(interaction.user.id)], ephemeral: true });
}

client.once("ready", async () => {
  console.log("Discord bot logged in as " + client.user.tag);
  client.user.setActivity("Discord verification", { type: ActivityType.Watching });
  try {
    const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);
    await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commandData });
    console.log("Registered " + commandData.length + " global slash commands for every server where the bot is installed");
  } catch (error) {
    console.error("Slash command registration failed: " + error.message);
  }
});

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;
  try {
    if (!interaction.inGuild()) {
      return interaction.reply({ content: "Use this command inside a Discord server where the bot is installed.", ephemeral: true });
    }
    if (interaction.commandName === "verify") return showVerify(interaction);
    if (!(await isVerified(interaction.user.id))) return showVerify(interaction);

    if (interaction.commandName === "ping") {
      const started = Date.now();
      await interaction.reply({ content: "🏓 Pong! API latency: " + Math.round(client.ws.ping) + "ms", ephemeral: true });
      return;
    }
    if (interaction.commandName === "help") {
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("🤖 Bot commands")
        .setDescription("Verify once with Discord OAuth2, then use commands in any server where this bot is installed.")
        .addFields(
          { name: "/ping", value: "Check bot latency.", inline: true },
          { name: "/userinfo [user]", value: "View basic user information.", inline: true },
          { name: "/avatar [user]", value: "Display a user's avatar.", inline: true },
          { name: "/serverinfo", value: "View server information.", inline: true },
          { name: "/botinfo", value: "View bot information.", inline: true },
          { name: "/uptime", value: "Check bot uptime.", inline: true },
          { name: "/verify", value: "Get the authorization button.", inline: true }
        ).setFooter({ text: "Auth Bot • Discord OAuth2" });
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
    if (interaction.commandName === "userinfo") {
      const user = interaction.options.getUser("user") || interaction.user;
      const member = interaction.options.getMember("user");
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("👤 " + user.username)
        .setThumbnail(user.displayAvatarURL({ size: 256 }))
        .addFields(
          { name: "Username", value: user.tag || user.username, inline: true },
          { name: "User ID", value: user.id, inline: true },
          { name: "Server nickname", value: member && member.nickname ? member.nickname : "Not set", inline: true },
          { name: "Bot account", value: user.bot ? "Yes" : "No", inline: true }
        );
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
    if (interaction.commandName === "serverinfo") {
      const guild = interaction.guild;
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("🏠 " + guild.name)
        .setThumbnail(guild.iconURL({ size: 256 }))
        .addFields(
          { name: "Server ID", value: guild.id, inline: true },
          { name: "Members", value: String(guild.memberCount), inline: true },
          { name: "Created", value: "<t:" + Math.floor(guild.createdTimestamp / 1000) + ":D>", inline: true }
        );
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
    if (interaction.commandName === "avatar") {
      const user = interaction.options.getUser("user") || interaction.user;
      const avatar = user.displayAvatarURL({ size: 1024, extension: "png" });
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("🖼️ " + user.username + "'s avatar").setImage(avatar).setURL(avatar);
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
    if (interaction.commandName === "botinfo") {
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("🤖 Auth Bot")
        .setThumbnail(client.user.displayAvatarURL()).setDescription("Discord OAuth2 verification and utility commands.")
        .addFields(
          { name: "Latency", value: Math.round(client.ws.ping) + "ms", inline: true },
          { name: "Servers", value: String(client.guilds.cache.size), inline: true },
          { name: "Library", value: "discord.js", inline: true }
        );
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
    if (interaction.commandName === "uptime") {
      const total = Math.floor((client.uptime || 0) / 1000);
      const days = Math.floor(total / 86400);
      const hours = Math.floor((total % 86400) / 3600);
      const minutes = Math.floor((total % 3600) / 60);
      const seconds = total % 60;
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("⏱️ Bot uptime")
        .setDescription(days + "d " + hours + "h " + minutes + "m " + seconds + "s");
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
  } catch (error) {
    console.error("Command /" + interaction.commandName + " failed: " + error.message);
    const reply = { content: "Something went wrong while running that command. Please try again shortly.", ephemeral: true };
    if (interaction.deferred || interaction.replied) return interaction.followUp(reply).catch(() => {});
    return interaction.reply(reply).catch(() => {});
  }
});

app.get("/", (_req, res) => res.type("html").send(htmlPage(
  "Discord verification",
  'Use the **Verify with Discord** button in the bot\'s message. This site uses official Discord OAuth2 and never asks for your Discord password.'
)));
app.get("/health", (_req, res) => res.status(200).json({ status: "ok" }));

// Lightweight per-process throttling for OAuth endpoints; protects against rapid retries.
const requestBuckets = new Map();
function limitOAuthRequests(req, res, next) {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || "unknown";
  let bucket = requestBuckets.get(key);
  if (!bucket || now - bucket.startedAt >= 15 * 60 * 1000) bucket = { startedAt: now, count: 0 };
  bucket.count += 1;
  requestBuckets.set(key, bucket);
  if (requestBuckets.size > 5000) {
    for (const [ip, item] of requestBuckets) if (now - item.startedAt >= 15 * 60 * 1000) requestBuckets.delete(ip);
  }
  if (bucket.count > 40) {
    res.setHeader("Retry-After", "900");
    return res.status(429).type("html").send(htmlPage("Slow down a moment", "Too many authorization attempts came from this connection. Wait a little and try again."));
  }
  return next();
}
app.get("/login", limitOAuthRequests, (req, res) => {
  const discordId = req.query.discord_id;
  if (typeof discordId !== "string" || !/^\d{17,20}$/.test(discordId)) {
    return res.status(400).type("html").send(htmlPage("Invalid verification link", "Return to Discord and click Verify in the bot's message."));
  }
  const state = signState({ discordId, nonce: crypto.randomBytes(24).toString("hex"), exp: Date.now() + 600000 });
  res.setHeader("Set-Cookie", "oauth_state=" + encodeURIComponent(state) + "; HttpOnly" + cookieSecureAttribute() + "; SameSite=Lax; Path=/; Max-Age=600");
  const authorizeUrl = new URL("https://discord.com/oauth2/authorize");
  authorizeUrl.search = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: "code", scope: "identify", state
  }).toString();
  console.log("Starting Discord OAuth authorization for app ID ending in " + String(CLIENT_ID).slice(-4));
  return res.redirect(302, authorizeUrl.toString());
});

app.get("/auth/callback", limitOAuthRequests, async (req, res) => {
  const { code, state, error } = req.query;
  if (error) {
    clearCookie(res);
    return res.status(400).type("html").send(htmlPage("Authorization cancelled", "Return to Discord and try again if you intended to verify."));
  }
  const cookieItem = (req.headers.cookie || "").split(";").map(p => p.trim()).find(p => p.startsWith("oauth_state="));
  const cookieState = cookieItem ? decodeURIComponent(cookieItem.slice("oauth_state=".length)) : null;
  clearCookie(res);
  if (typeof state !== "string" || !cookieState || state !== cookieState || !verifyState(state)) {
    return res.status(400).type("html").send(htmlPage("Verification failed", "The verification session is invalid or expired. Return to Discord and click Verify again."));
  }
  const statePayload = verifyState(state);
  if (typeof code !== "string" || !code) {
    return res.status(400).type("html").send(htmlPage("Verification failed", "Discord did not return an authorization code. Please try again."));
  }
  try {
    const tokenResponse = await axios.post("https://discord.com/api/v10/oauth2/token",
      new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: "authorization_code",
        code, redirect_uri: REDIRECT_URI
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 10000 }
    );
    const accessToken = tokenResponse.data.access_token;
    const profile = await axios.get("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: "Bearer " + accessToken }, timeout: 10000
    });
    const user = profile.data;
    if (!user || !user.id || user.id !== statePayload.discordId) {
      return res.status(403).type("html").send(htmlPage(
        "Wrong Discord account",
        "You authorized a different account from the one that clicked Verify. Return to Discord, switch to the correct account, and click Verify again."
      ));
    }
    await markVerified(user.id);
    return res.status(200).type("html").send(htmlPage(
      "Verification complete",
      "Successfully verified as <strong>" + escapeHtml(user.global_name || user.username) +
      "</strong>. Your account is now authorized to use the bot in any server where it is installed. No role was added. Return to Discord and retry your command."
    ));
  } catch (err) {
    const status = err.response && err.response.status;
    console.error("OAuth verification/database save failed: " + (status || err.message));
    const message = "Discord authorization or saving verification failed. Please return to Discord and try again.";
    return res.status(502).type("html").send(htmlPage("Verification could not be completed", message));
  }
});
app.use((_req, res) => res.status(404).type("text").send("Not found"));
const httpServer = app.listen(PORT, "0.0.0.0", () => console.log("Auth Bot web server listening on port " + PORT));
client.login(DISCORD_TOKEN).catch(error => {
  console.error("Discord bot login failed: " + error.message);
  process.exit(1);
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(signal + " received; shutting down gracefully");
  const forceExit = setTimeout(() => process.exit(1), 10000);
  forceExit.unref();
  try {
    await new Promise(resolve => httpServer.close(resolve));
    client.destroy();
    await db.end();
    clearTimeout(forceExit);
    process.exit(0);
  } catch (error) {
    console.error("Graceful shutdown failed: " + error.message);
    process.exit(1);
  }
}
process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));
process.on("unhandledRejection", error => {
  console.error("Unhandled promise rejection:", error instanceof Error ? error.message : String(error));
});
process.on("uncaughtException", error => {
  console.error("Uncaught exception:", error.message);
  shutdown("uncaughtException");
});
