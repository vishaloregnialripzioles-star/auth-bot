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
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https://cdn.discordapp.com https://media.discordapp.net; base-uri 'none'; frame-ancestors 'none';");
  next();
});

const PORT = Number(process.env.PORT) || 3000;
const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, DATABASE_URL } = process.env;
const STATE_SECRET = process.env.STATE_SECRET;
// Set PUBLIC_URL to the exact public Render service origin (for example, https://auth-bot-xxxx.onrender.com).
// This keeps the Discord button pointed at the deployed website even if REDIRECT_URI is accidentally misconfigured.
const PUBLIC_URL = process.env.PUBLIC_URL;
const required = { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, DATABASE_URL, STATE_SECRET };
const missing = Object.keys(required).filter((key) => !required[key]);
if (missing.length) {
  console.error("Missing required environment variables: " + missing.join(", "));
  process.exit(1);
}
if (STATE_SECRET.length < 32) {
  console.error("STATE_SECRET must be at least 32 characters long and should be a random secret unique from DISCORD_CLIENT_SECRET.");
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
  if (publicUrl.origin !== redirect.origin) throw new Error("PUBLIC_URL and REDIRECT_URI must use the same host.");
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
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top,#252b58 0%,#111322 55%,#0b0c14 100%);color:#f7f7fb;font-family:Segoe UI,system-ui,-apple-system,sans-serif}main{width:min(100%,560px);background:rgba(19,23,39,.8);border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,.45)}h1{margin:0 0 12px;font-size:clamp(2rem,5vw,2.5rem)}p{margin:0;line-height:1.65;color:#e8ebff}strong{color:#fff}a{color:#9bb3ff;text-decoration:none}a:hover{text-decoration:underline}.meta{margin-top:18px;color:#b9bfd9;font-size:.92rem}button{appearance:none;border:none;border-radius:12px;padding:12px 18px;background:linear-gradient(135deg,#5865f2,#4752c4);color:#fff;font-weight:700;cursor:pointer}button:hover{filter:brightness(1.08)}@media(max-width:640px){main{padding:22px 18px;border-radius:16px}}</style></head><body><main><h1>' +
    escapeHtml(title) + '</h1><p>' + message + '</p><div class="meta">Auth Bot • Discord OAuth2</div></main></body></html>';
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  connectionTimeoutMillis: 10000
});
const dbReady = db.query(`CREATE TABLE IF NOT EXISTS verified_users (
  discord_id VARCHAR(20) PRIMARY KEY,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`).then(() => db.query(`CREATE TABLE IF NOT EXISTS app_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`)).then(() => console.log("Verified-user database ready")).catch(error => {
  console.error("Verified-user database initialization failed: " + error.message);
  process.exit(1);
});
async function getTargetGuild() {
  await dbReady;
  const result = await db.query("SELECT setting_value FROM app_settings WHERE setting_key = $1", ["target_guild_id"]);
  const guildId = result.rows[0] && result.rows[0].setting_value;
  if (!guildId) return null;
  try {
    const guild = await client.guilds.fetch(guildId);
    return { id: guild.id, name: guild.name };
  } catch {
    return { id: guildId, name: "configured Discord server" };
  }
}
async function setTargetGuild(guildId) {
  await dbReady;
  await db.query(
    "INSERT INTO app_settings (setting_key, setting_value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()",
    ["target_guild_id", guildId]
  );
}
async function isVerified(userId) {
  await dbReady;
  const result = await db.query("SELECT 1 FROM verified_users WHERE discord_id = $1", [userId]);
  return result.rowCount > 0;
}
async function markVerified(userId) {
  await dbReady;
  await db.query("INSERT INTO verified_users (discord_id) VALUES ($1) ON CONFLICT (discord_id) DO NOTHING", [userId]);
}

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
const commandData = [
  new SlashCommandBuilder().setName("ping").setDescription("Check whether the bot is online"),
  new SlashCommandBuilder().setName("help").setDescription("Show available commands"),
  new SlashCommandBuilder().setName("verify").setDescription("Get the authorization button"),
  new SlashCommandBuilder().setName("setguild").setDescription("Set the server used for consent-based joining")
    .addStringOption(o => o.setName("guild_id").setDescription("Server ID (the bot must be installed there)").setRequired(true)),
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
    .setDescription("You need to verify your Discord account before using this bot's commands.\n\nPress **Verify with Discord** below and authorize the same account you use in this server. After verification, return to Discord and retry your command.")
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

client.on("guildMemberAdd", async member => {
  if (member.user.bot) return;
  try {
    await member.send({
      embeds: [verifyEmbed()],
      components: [verifyRow(member.id)]
    });
    console.log("Sent verification prompt to newly joined user: " + member.user.tag);
  } catch (error) {
    console.log("Could not DM verification prompt to " + member.user.tag + ": " + error.message);
  }
});

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;
  try {
    if (!interaction.inGuild()) {
      return interaction.reply({ content: "Use this command inside a Discord server where the bot is installed.", ephemeral: true });
    }
    if (interaction.commandName === "verify") return showVerify(interaction);
    if (interaction.commandName === "setguild") {
      if (!interaction.memberPermissions || !interaction.memberPermissions.has("ManageGuild")) return interaction.reply({ content: "You need Manage Server permission to change the target server.", ephemeral: true });
      const guildId = interaction.options.getString("guild_id", true).trim();
      if (!/^\\d{17,20}$/.test(guildId)) return interaction.reply({ content: "Enter a valid Discord server ID.", ephemeral: true });
      let guild;
      try { guild = await client.guilds.fetch(guildId); } catch { return interaction.reply({ content: "I cannot access that server. Invite the bot there first, then try again.", ephemeral: true }); }
      await setTargetGuild(guild.id);
      return interaction.reply({ content: "✅ Target server set to **" + guild.name.replace(/[*_~`|>]/g, "") + "** (`" + guild.id + "`). The setting persists across redeploys.", ephemeral: true });
    }
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
          { name: "/verify", value: "Get the authorization button.", inline: true },
          { name: "/setguild guild_id", value: "Set target server (Manage Server required).", inline: true }
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
app.get("/login", limitOAuthRequests, async (req, res) => {
  const discordId = req.query.discord_id;
  if (typeof discordId !== "string" || !/^\d{17,20}$/.test(discordId)) {
    return res.status(400).type("html").send(htmlPage("Invalid verification link", "Return to Discord and click Verify in the bot's message."));
  }
  const targetGuild = await getTargetGuild();
  if (!targetGuild) return res.status(503).type("html").send(htmlPage("Server not configured", "A server administrator must run /setguild before accounts can authorize joining."));
  const continueUrl = new URL("/oauth/start", APP_BASE_URL);
  continueUrl.searchParams.set("discord_id", discordId);
  return res.status(200).type("html").send(htmlPage(
    "Authorize and join server",
    'By continuing, you authorize this app to read your basic Discord profile and request to add <strong>this account only</strong> to <strong>' +
    escapeHtml(targetGuild.name) + '</strong>. No other accounts will be added on your behalf. You can cancel on Discord. <p style="margin-top:18px"><a href="' +
    escapeHtml(continueUrl.toString()) + '"><button type="button">Continue to Discord authorization</button></a></p>'
  ));
});
app.get("/oauth/start", limitOAuthRequests, (req, res) => {
  const discordId = req.query.discord_id;
  if (typeof discordId !== "string" || !/^\d{17,20}$/.test(discordId)) {
    return res.status(400).type("html").send(htmlPage("Invalid authorization link", "Return to Discord and click Verify again."));
  }
  const state = signState({ discordId, nonce: crypto.randomBytes(24).toString("hex"), exp: Date.now() + 600000 });
  res.setHeader("Set-Cookie", "oauth_state=" + encodeURIComponent(state) + "; HttpOnly" + cookieSecureAttribute() + "; SameSite=Lax; Path=/; Max-Age=600");
  const authorizeUrl = new URL("https://discord.com/oauth2/authorize");
  authorizeUrl.search = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: "code", scope: "identify guilds.join", state
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
    let joinMessage = "";
    try {
      const joinResult = await axios.put(
        "https://discord.com/api/v10/guilds/" + targetGuild.id + "/members/" + user.id,
        { access_token: accessToken },
        { headers: { Authorization: "Bot " + DISCORD_TOKEN, "Content-Type": "application/json" }, timeout: 10000 }
      );
      joinMessage = joinResult.status === 201
        ? " This account has joined <strong>" + escapeHtml(targetGuild.name) + "</strong>."
        : " This account already belonged to <strong>" + escapeHtml(targetGuild.name) + "</strong>.";
    } catch (joinError) {
      const joinStatus = joinError.response && joinError.response.status;
      console.error("Consented server join failed: " + (joinStatus || joinError.message));
      joinMessage = " Your account was verified, but the server join could not be completed. Please use the server's official invite link or contact its moderators.";
    }
    await markVerified(user.id);
    return res.status(200).type("html").send(htmlPage(
      "Authorization complete",
      "Successfully authorized as <strong>" + escapeHtml(user.global_name || user.username) +
      "</strong>." + joinMessage + " Return to Discord and retry your command."
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
