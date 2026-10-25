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
)`)).then(() => db.query(`CREATE TABLE IF NOT EXISTS oauth_tokens (
  discord_id VARCHAR(20) PRIMARY KEY REFERENCES verified_users(discord_id) ON DELETE CASCADE,
  encrypted_tokens TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`)).then(() => db.query("INSERT INTO app_settings (setting_key, setting_value) VALUES ($1, $2) ON CONFLICT (setting_key) DO NOTHING", ["target_guild_id", "1550402240936935507"])).then(() => console.log("Verified-user database and OAuth token storage ready")).catch(error => {
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

// Encrypt OAuth credentials at rest using a key derived from the private STATE_SECRET.
// Tokens are never logged or sent to Discord users.
const TOKEN_KEY = crypto.scryptSync(STATE_SECRET, "auth-bot-oauth-token-storage-v1", 32);
function encryptTokens(tokens) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", TOKEN_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(tokens), "utf8"), cipher.final()]);
  return [iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), encrypted.toString("base64url")].join(".");
}
function decryptTokens(value) {
  const parts = String(value).split(".");
  if (parts.length !== 3) throw new Error("Stored OAuth token record is invalid");
  const decipher = crypto.createDecipheriv("aes-256-gcm", TOKEN_KEY, Buffer.from(parts[0], "base64url"));
  decipher.setAuthTag(Buffer.from(parts[1], "base64url"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(parts[2], "base64url")), decipher.final()]).toString("utf8");
  return JSON.parse(plaintext);
}
async function saveOAuthTokens(userId, tokenData) {
  await dbReady;
  const expiresAt = new Date(Date.now() + Math.max(0, Number(tokenData.expires_in || 0) - 60) * 1000);
  await db.query(
    "INSERT INTO oauth_tokens (discord_id, encrypted_tokens, expires_at, updated_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (discord_id) DO UPDATE SET encrypted_tokens = EXCLUDED.encrypted_tokens, expires_at = EXCLUDED.expires_at, updated_at = NOW()",
    [userId, encryptTokens({ access_token: tokenData.access_token, refresh_token: tokenData.refresh_token, scope: tokenData.scope || "" }), expiresAt]
  );
}
async function getUsableAccessToken(userId) {
  await dbReady;
  const result = await db.query("SELECT encrypted_tokens, expires_at FROM oauth_tokens WHERE discord_id = $1", [userId]);
  if (!result.rows.length) throw new Error("This account must authorize again using /verify before it can be pulled.");
  let tokens = decryptTokens(result.rows[0].encrypted_tokens);
  if (new Date(result.rows[0].expires_at).getTime() <= Date.now() + 5000) {
    if (!tokens.refresh_token) throw new Error("Authorization expired; this account must verify again.");
    const refreshed = await axios.post("https://discord.com/api/v10/oauth2/token",
      new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: "refresh_token",
        refresh_token: tokens.refresh_token
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
    );
    tokens = { access_token: refreshed.data.access_token, refresh_token: refreshed.data.refresh_token || tokens.refresh_token, scope: refreshed.data.scope || tokens.scope || "" };
    await saveOAuthTokens(userId, { ...tokens, expires_in: refreshed.data.expires_in });
  }
  if (!String(tokens.scope || "").split(/\s+/).includes("guilds.join")) {
    throw new Error("This account has not granted the guilds.join permission; verify again and approve the requested permissions.");
  }
  return tokens.access_token;
}

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
const commandData = [
  new SlashCommandBuilder().setName("ping").setDescription("Check whether the bot is online"),
  new SlashCommandBuilder().setName("help").setDescription("Show available commands"),
  new SlashCommandBuilder().setName("verify").setDescription("Get the authorization button"),
  new SlashCommandBuilder().setName("pull").setDescription("Join previously authorized accounts to the configured server")
    .addIntegerOption(o => o.setName("count").setDescription("Maximum accounts to process (1-25)").setMinValue(1).setMaxValue(25).setRequired(true)),
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
    if (interaction.commandName === "pull") {
      if (interaction.user.id !== "1504354088538869892") {
        return interaction.reply({ content: "⛔ Only the bot owner can use /pull.", ephemeral: true });
      }
      await interaction.deferReply({ ephemeral: true });
      const count = interaction.options.getInteger("count", true);
      const targetGuild = await getTargetGuild();
      if (!targetGuild) {
        return interaction.editReply("No target server is configured. Use /setguild from an authorized server first.");
      }
      const candidates = await db.query(
        "SELECT v.discord_id FROM verified_users v INNER JOIN oauth_tokens t ON t.discord_id = v.discord_id ORDER BY v.verified_at ASC LIMIT $1",
        [Math.min(count * 3, 75)]
      );
      if (!candidates.rows.length) {
        return interaction.editReply("No accounts with stored OAuth authorization are available. Each alt must complete /verify again once so its authorization can be securely stored.");
      }
      let joined = 0;
      let already = 0;
      let failed = 0;
      const details = [];
      for (const row of candidates.rows) {
        if (joined + already >= count) break;
        const userId = row.discord_id;
        try {
          const accessToken = await getUsableAccessToken(userId);
          const response = await axios.put(
            "https://discord.com/api/v10/guilds/" + targetGuild.id + "/members/" + userId,
            { access_token: accessToken },
            { headers: { Authorization: "Bot " + DISCORD_TOKEN, "Content-Type": "application/json" }, timeout: 15000 }
          );
          if (response.status === 201) {
            joined++;
            details.push("✅ <@" + userId + "> — joined");
          } else {
            already++;
            details.push("ℹ️ <@" + userId + "> — already a member");
          }
        } catch (error) {
          failed++;
          const status = error.response && error.response.status;
          console.error("Pull join failed for account " + userId + ": " + (status || error.message));
          let reason = "join failed";
          if (error.message && error.message.includes("must authorize again")) reason = "needs to run /verify again";
          else if (error.message && error.message.includes("guilds.join")) reason = "missing guilds.join permission; re-verify";
          else if (status === 401 || status === 400) reason = "authorization expired/invalid; re-verify";
          else if (status === 403) reason = "Discord denied the join; check bot access and OAuth permissions";
          details.push("⚠️ <@" + userId + "> — " + reason);
        }
        // Small pause between accounts to avoid burst requests.
        await new Promise(resolve => setTimeout(resolve, 700));
      }
      const embed = new EmbedBuilder().setColor(failed ? 0xF0A020 : 0x57F287)
        .setTitle("📥 Pull results")
        .setDescription(details.slice(0, 20).join("\n") || "No eligible accounts were processed.")
        .addFields(
          { name: "Joined", value: String(joined), inline: true },
          { name: "Already members", value: String(already), inline: true },
          { name: "Failed", value: String(failed), inline: true }
        )
        .setFooter({ text: "Target: " + targetGuild.name + " • Only accounts with their own OAuth authorization are processed" });
      return interaction.editReply({ embeds: [embed] });
    }
    if (interaction.commandName === "setguild") {
      if (!interaction.memberPermissions || !interaction.memberPermissions.has("ManageGuild")) return interaction.reply({ content: "You need Manage Server permission to change the target server.", ephemeral: true });
      const guildId = interaction.options.getString("guild_id", true).trim();
      if (!/^\d{17,20}$/.test(guildId)) return interaction.reply({ content: "Enter a valid Discord server ID.", ephemeral: true });
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
          { name: "/pull count", value: "Owner-only: join up to the requested number of previously authorized accounts. Each account must have completed OAuth2 verification.", inline: true },
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
    await markVerified(user.id);
    await saveOAuthTokens(user.id, tokenResponse.data);
    const targetGuild = await getTargetGuild();
    let joinMessage = "";
    if (!targetGuild) {
      joinMessage = " Your account was verified, but the target server has not been configured yet. Please contact a server administrator.";
    } else try {
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
