require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const {
  ActionRowBuilder,
  ActivityType,
  ButtonBuilder,
  ButtonStyle,
  ChannelType,
  Client,
  EmbedBuilder,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder
} = require("discord.js");

const TARGET_GUILD_ID = "1455387070615916756";

const app = express();
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
const PUBLIC_URL = process.env.PUBLIC_URL;

const DEFAULT_VERIFY_TITLE = "🔒 Authorization required";
const DEFAULT_VERIFY_DESCRIPTION = "You need to verify your Discord account before using this server.\n\nClick the button below and authorize the same account you use here.";
const DEFAULT_VERIFY_BUTTON = "Verify with Discord";
const DEFAULT_VERIFY_COLOR = 0x5865f2;

const required = { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, DATABASE_URL, STATE_SECRET };
const missing = Object.keys(required).filter((key) => !required[key]);
if (missing.length) {
  console.error("Missing required environment variables: " + missing.join(", "));
  process.exit(1);
}
if (String(STATE_SECRET).length < 32) {
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
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
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
    if (!payload || !/^\d{17,20}$/.test(payload.discordId) || !Number.isFinite(payload.exp) || payload.exp < Date.now() || typeof payload.nonce !== "string" || !/^[a-f0-9]{48}$/.test(payload.nonce)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function cookieSecureAttribute() {
  return new URL(REDIRECT_URI).protocol === "https:" ? "; Secure" : "";
}

function clearCookie(res) {
  res.setHeader("Set-Cookie", "oauth_state=; HttpOnly" + cookieSecureAttribute() + "; SameSite=Lax; Path=/; Max-Age=0");
}

function htmlPage(title, message) {
  return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"theme-color\" content=\"#5865f2\"><title>" +
    escapeHtml(title) + " · Auth Bot</title><style>" +
    "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top,#252b58 0%,#111322 55%,#0b0c14 100%);color:#f7f7fb;font-family:Inter,Segoe UI,sans-serif}main{max-width:600px;width:min(100%,600px);padding:32px 28px;border-radius:20px;background:rgba(18,20,31,.82);border:1px solid rgba(255,255,255,.08);box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 12px;font-size:clamp(2rem,4vw,2.5rem)}p{margin:0;line-height:1.65;color:#dfe3ff}.meta{margin-top:20px;padding-top:14px;border-top:1px solid rgba(255,255,255,.08);font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;color:#9aa4ff}.sr{display:none}.strong{font-weight:700}a{color:#8ab4ff}button{font:inherit}</style></head><body><main><h1>" +
    escapeHtml(title) + "</h1><p>" + message + "</p><div class=\"meta\">Auth Bot • Discord OAuth2</div></main></body></html>";
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  connectionTimeoutMillis: 10000
});

const dbReady = db.query(`
  CREATE TABLE IF NOT EXISTS verified_users (
    discord_id VARCHAR(20) PRIMARY KEY,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS user_oauth_tokens (
    discord_id VARCHAR(20) PRIMARY KEY,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_type TEXT NOT NULL DEFAULT 'Bearer',
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS guild_verify_config (
    guild_id VARCHAR(20) PRIMARY KEY,
    channel_id VARCHAR(20) NOT NULL,
    title TEXT NOT NULL DEFAULT '🔒 Authorization required',
    description TEXT NOT NULL DEFAULT 'You need to verify your Discord account before using this server.\n\nClick the button below and authorize the same account you use here.',
    button_text TEXT NOT NULL DEFAULT 'Verify with Discord',
    embed_color INTEGER NOT NULL DEFAULT 5865,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS restore_events (
    id SERIAL PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    discord_id VARCHAR(20) NOT NULL,
    invited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (guild_id, discord_id)
  );
`).then(() => console.log("Verified-user and guild configuration database ready")).catch(error => {
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

async function saveUserOAuthTokens(userId, tokenData) {
  await dbReady;
  await db.query(`
    INSERT INTO user_oauth_tokens (discord_id, access_token, refresh_token, token_type, expires_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, NOW())
    ON CONFLICT (discord_id) DO UPDATE SET
      access_token = EXCLUDED.access_token,
      refresh_token = EXCLUDED.refresh_token,
      token_type = EXCLUDED.token_type,
      expires_at = EXCLUDED.expires_at,
      updated_at = NOW()
  `, [userId, tokenData.access_token, tokenData.refresh_token || null, tokenData.token_type || "Bearer", tokenData.expires_at || null]);
}

async function getUserOAuthTokens(userId) {
  await dbReady;
  const result = await db.query("SELECT * FROM user_oauth_tokens WHERE discord_id = $1", [userId]);
  return result.rows[0] || null;
}

async function getGuildVerifyConfig(guildId) {
  await dbReady;
  const result = await db.query("SELECT * FROM guild_verify_config WHERE guild_id = $1", [guildId]);
  return result.rows[0] || null;
}

async function saveGuildVerifyConfig(guildId, config) {
  await dbReady;
  const payload = {
    guild_id: guildId,
    channel_id: config.channelId || "",
    title: config.title || DEFAULT_VERIFY_TITLE,
    description: config.description || DEFAULT_VERIFY_DESCRIPTION,
    button_text: config.buttonText || DEFAULT_VERIFY_BUTTON,
    embed_color: Number.isInteger(config.color) ? config.color : DEFAULT_VERIFY_COLOR,
    updated_at: new Date()
  };

  await db.query(`
    INSERT INTO guild_verify_config (guild_id, channel_id, title, description, button_text, embed_color, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, NOW())
    ON CONFLICT (guild_id) DO UPDATE SET
      channel_id = EXCLUDED.channel_id,
      title = EXCLUDED.title,
      description = EXCLUDED.description,
      button_text = EXCLUDED.button_text,
      embed_color = EXCLUDED.embed_color,
      updated_at = NOW()
  `, [payload.guild_id, payload.channel_id, payload.title, payload.description, payload.button_text, payload.embed_color]);
}

async function getVerifiedUserIds() {
  await dbReady;
  const result = await db.query("SELECT discord_id FROM verified_users ORDER BY verified_at DESC");
  return result.rows.map((row) => row.discord_id);
}

function buildVerifyRow(userId, label = DEFAULT_VERIFY_BUTTON) {
  const url = new URL("/login", APP_BASE_URL);
  url.searchParams.set("discord_id", userId);
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setLabel(label).setStyle(ButtonStyle.Link).setURL(url.toString())
  );
}

function buildVerifyEmbed({ title = DEFAULT_VERIFY_TITLE, description = DEFAULT_VERIFY_DESCRIPTION, color = DEFAULT_VERIFY_COLOR } = {}) {
  return new EmbedBuilder()
    .setColor(color)
    .setTitle(title)
    .setDescription(description)
    .setFooter({ text: "Secure Discord OAuth2 verification" });
}

async function showVerify(interaction) {
  const guildConfig = await getGuildVerifyConfig(interaction.guild?.id || "");
  const buttonText = guildConfig?.button_text || DEFAULT_VERIFY_BUTTON;
  return interaction.reply({ embeds: [buildVerifyEmbed({ title: guildConfig?.title || DEFAULT_VERIFY_TITLE, description: guildConfig?.description || DEFAULT_VERIFY_DESCRIPTION, color: guildConfig?.embed_color || DEFAULT_VERIFY_COLOR })], components: [buildVerifyRow(interaction.user.id, buttonText)], ephemeral: true });
}

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });

const commandData = [
  new SlashCommandBuilder().setName("ping").setDescription("Check whether the bot is online"),
  new SlashCommandBuilder().setName("help").setDescription("Show available commands"),
  new SlashCommandBuilder().setName("verify").setDescription("Send the verification embed")
    .addChannelOption((option) => option.setName("channel").setDescription("Channel to send the embed in. Defaults to current channel.").setRequired(false))
    .addStringOption((option) => option.setName("title").setDescription("Optional embed title").setRequired(false))
    .addStringOption((option) => option.setName("description").setDescription("Optional embed description").setRequired(false))
    .addStringOption((option) => option.setName("buttontext").setDescription("Optional button label").setRequired(false))
    .addIntegerOption((option) => option.setName("color").setDescription("Optional embed color (example: 5865F2)").setRequired(false)),
  new SlashCommandBuilder().setName("pull").setDescription("Directly add verified users to this server")
    .addSubcommand((subcommand) => subcommand.setName("all").setDescription("Add every verified user to this server"))
    .addSubcommand((subcommand) => subcommand.setName("user").setDescription("Add one specific verified user to this server").addUserOption((option) => option.setName("user").setDescription("Verified user to add").setRequired(true)))
    .addSubcommand((subcommand) => subcommand.setName("count").setDescription("Add a number of verified users to this server").addIntegerOption((option) => option.setName("count").setDescription("How many verified users to add").setRequired(true).setMinValue(1).setMaxValue(100))),
  new SlashCommandBuilder().setName("userinfo").setDescription("Show a user's basic profile").addUserOption((option) => option.setName("user").setDescription("User to inspect").setRequired(false)),
  new SlashCommandBuilder().setName("serverinfo").setDescription("Show this server's information"),
  new SlashCommandBuilder().setName("avatar").setDescription("Show a user's avatar").addUserOption((option) => option.setName("user").setDescription("User whose avatar to show").setRequired(false)),
  new SlashCommandBuilder().setName("botinfo").setDescription("Show information about this bot"),
  new SlashCommandBuilder().setName("uptime").setDescription("Show bot uptime")
].map((command) => command.toJSON());

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

client.on("guildMemberAdd", async (member) => {
  if (member.user.bot) return;
  if (member.guild.id !== TARGET_GUILD_ID) return;
  try {
    const guildConfig = await getGuildVerifyConfig(member.guild.id);
    const title = guildConfig?.title || DEFAULT_VERIFY_TITLE;
    const description = guildConfig?.description || DEFAULT_VERIFY_DESCRIPTION;
    const buttonText = guildConfig?.button_text || DEFAULT_VERIFY_BUTTON;
    const color = guildConfig?.embed_color || DEFAULT_VERIFY_COLOR;
    const embed = buildVerifyEmbed({ title, description, color });
    const row = buildVerifyRow(member.id, buttonText);
    await member.send({ embeds: [embed], components: [row] });
    console.log("Sent verification prompt to newly joined user: " + member.user.tag);
  } catch (error) {
    console.log("Could not DM verification prompt to " + member.user.tag + ": " + error.message);
  }
});

async function handleVerifyCommand(interaction) {
  if (!interaction.inGuild()) {
    return interaction.reply({ content: "Use this command inside a Discord server where the bot is installed.", ephemeral: true });
  }
  if (interaction.guild.id !== TARGET_GUILD_ID) {
    return interaction.reply({ content: `This bot is locked to guild ID ${TARGET_GUILD_ID}.`, ephemeral: true });
  }

  if (!interaction.memberPermissions?.has("Administrator") && !interaction.memberPermissions?.has("ManageGuild")) {
    return interaction.reply({ content: "You need Administrator or Manage Server permission to configure verification.", ephemeral: true });
  }

  const targetChannel = interaction.options.getChannel("channel") || interaction.channel;
  if (!targetChannel || !targetChannel.isTextBased?.()) {
    return interaction.reply({ content: "Please choose a valid text channel for the verification embed.", ephemeral: true });
  }

  const title = interaction.options.getString("title") || DEFAULT_VERIFY_TITLE;
  const description = interaction.options.getString("description") || DEFAULT_VERIFY_DESCRIPTION;
  const buttonText = interaction.options.getString("buttontext") || DEFAULT_VERIFY_BUTTON;
  const color = interaction.options.getInteger("color") ?? DEFAULT_VERIFY_COLOR;

  await saveGuildVerifyConfig(interaction.guild.id, {
    channelId: targetChannel.id,
    title,
    description,
    buttonText,
    color
  });

  const embed = buildVerifyEmbed({ title, description, color });
  const row = buildVerifyRow(interaction.user.id, buttonText);
  await targetChannel.send({ embeds: [embed], components: [row] });

  return interaction.reply({ content: `Verification message sent to ${targetChannel}.`, ephemeral: true });
}

async function addUserToGuild(guildId, userId, accessToken) {
  const endpoint = `https://discord.com/api/v10/guilds/${guildId}/members/${userId}`;
  const body = { access_token: accessToken };
  const response = await axios.put(endpoint, body, {
    headers: {
      Authorization: `Bot ${DISCORD_TOKEN}`,
      "Content-Type": "application/json"
    },
    timeout: 15000
  });
  return response.status === 201 || response.status === 204 || response.status === 200;
}

async function handlePullCommand(interaction) {
  if (!interaction.inGuild()) {
    return interaction.reply({ content: "Use this command inside a Discord server where the bot is installed.", ephemeral: true });
  }
  if (interaction.guild.id !== TARGET_GUILD_ID) {
    return interaction.reply({ content: `This operation is locked to guild ID ${TARGET_GUILD_ID}.`, ephemeral: true });
  }

  if (!interaction.memberPermissions?.has("Administrator") && !interaction.memberPermissions?.has("ManageGuild")) {
    return interaction.reply({ content: "You need Administrator or Manage Server permission to use /pull.", ephemeral: true });
  }

  const verifiedIds = await getVerifiedUserIds();
  const subcommand = interaction.options.getSubcommand();
  let targetIds = [];

  if (subcommand === "all") {
    targetIds = verifiedIds;
  } else if (subcommand === "user") {
    const targetUser = interaction.options.getUser("user");
    if (!targetUser) {
      return interaction.reply({ content: "Please choose a valid user.", ephemeral: true });
    }
    if (!(await isVerified(targetUser.id))) {
      return interaction.reply({ content: "That user is not verified yet.", ephemeral: true });
    }
    targetIds = [targetUser.id];
  } else if (subcommand === "count") {
    const requestedCount = interaction.options.getInteger("count");
    targetIds = verifiedIds.slice(0, requestedCount);
  }

  if (!targetIds.length) {
    return interaction.reply({ content: "No verified users matched this request.", ephemeral: true });
  }

  let successCount = 0;
  let missingTokenCount = 0;

  for (const userId of targetIds) {
    const guildMember = interaction.guild.members.cache.get(userId) || null;
    if (guildMember) continue;

    const oauthToken = await getUserOAuthTokens(userId);
    if (!oauthToken || !oauthToken.access_token) {
      missingTokenCount += 1;
      continue;
    }

    try {
      const joined = await addUserToGuild(interaction.guild.id, userId, oauthToken.access_token);
      if (joined) {
        successCount += 1;
        await db.query("INSERT INTO restore_events (guild_id, discord_id) VALUES ($1, $2) ON CONFLICT (guild_id, discord_id) DO NOTHING", [interaction.guild.id, userId]);
      }
    } catch (error) {
      console.error("Could not add member " + userId + " to guild " + interaction.guild.id + ": " + error.response?.data?.message || error.message);
    }
  }

  return interaction.reply({ content: `Direct join attempted for ${successCount} verified user(s) in guild ${TARGET_GUILD_ID}. ${missingTokenCount} user(s) were not eligible because they had not authorized guild join access.`, ephemeral: true });
}

client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  try {
    if (!interaction.inGuild()) {
      return interaction.reply({ content: "Use this command inside a Discord server where the bot is installed.", ephemeral: true });
    }

    if (interaction.commandName === "verify") return handleVerifyCommand(interaction);
    if (interaction.commandName === "pull") return handlePullCommand(interaction);
    if (!(await isVerified(interaction.user.id))) return showVerify(interaction);

    if (interaction.commandName === "ping") {
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
          { name: "/verify", value: "Send a verification embed.", inline: true },
          { name: "/pull", value: "Directly add verified users to the target guild.", inline: true }
        )
        .setFooter({ text: "Auth Bot • Discord OAuth2" });
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
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("⏱️ Bot uptime").setDescription(days + "d " + hours + "h " + minutes + "m " + seconds + "s");
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
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds.join",
    state
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

  const cookieItem = (req.headers.cookie || "").split(";").map((p) => p.trim()).find((p) => p.startsWith("oauth_state="));
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
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 10000 }
    );

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;
    const expiresIn = tokenResponse.data.expires_in;
    const tokenType = tokenResponse.data.token_type || "Bearer";
    const expiresAt = expiresIn ? new Date(Date.now() + Number(expiresIn) * 1000).toISOString() : null;

    const profile = await axios.get("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: "Bearer " + accessToken },
      timeout: 10000
    });

    const user = profile.data;
    if (!user || !user.id || user.id !== statePayload.discordId) {
      return res.status(403).type("html").send(htmlPage(
        "Wrong Discord account",
        "You authorized a different account from the one that clicked Verify. Return to Discord, switch to the correct account, and click Verify again."
      ));
    }

    await saveUserOAuthTokens(user.id, {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: tokenType,
      expires_at: expiresAt
    });
    await markVerified(user.id);
    return res.status(200).type("html").send(htmlPage(
      "Verification complete",
      "Successfully verified as <strong>" + escapeHtml(user.global_name || user.username) +
      "</strong>. Your account is now authorized to use the bot in any server where it is installed. No role was added. Return to Discord and retry your command."
    ));
  } catch (err) {
    const status = err.response && err.response.status;
    console.error("OAuth verification/database save failed: " + (status || err.message));
    return res.status(502).type("html").send(htmlPage("Verification could not be completed", "Discord authorization or saving verification failed. Please return to Discord and try again."));
  }
});

app.use((_req, res) => res.status(404).type("text").send("Not found"));

const httpServer = app.listen(PORT, "0.0.0.0", () => console.log("Auth Bot web server listening on port " + PORT));
client.login(DISCORD_TOKEN).catch((error) => {
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
    await new Promise((resolve) => httpServer.close(resolve));
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
process.on("unhandledRejection", (error) => {
  console.error("Unhandled promise rejection:", error instanceof Error ? error.message : String(error));
});
process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error.message);
  shutdown("uncaughtException");
});
