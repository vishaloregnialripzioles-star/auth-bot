require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("node:crypto");
const {
  ActionRowBuilder, ActivityType, ButtonBuilder, ButtonStyle, Client,
  EmbedBuilder, GatewayIntentBits, REST, Routes, SlashCommandBuilder
} = require("discord.js");

const app = express();
app.disable("x-powered-by");
app.use((_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

const PORT = Number(process.env.PORT) || 3000;
const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, GUILD_ID, VERIFY_ROLE_ID } = process.env;
const STATE_SECRET = process.env.STATE_SECRET || CLIENT_SECRET;
const required = { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DISCORD_TOKEN, GUILD_ID, VERIFY_ROLE_ID };
const missing = Object.keys(required).filter((key) => !required[key]);
if (missing.length) {
  console.error("Missing required environment variables: " + missing.join(", "));
  process.exit(1);
}
try {
  const redirect = new URL(REDIRECT_URI);
  if (redirect.protocol !== "https:" && redirect.hostname !== "localhost") throw new Error("REDIRECT_URI must use HTTPS.");
} catch (error) {
  console.error("Invalid REDIRECT_URI: " + error.message);
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
  if (typeof state !== "string") return null;
  const parts = state.split(".");
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac("sha256", STATE_SECRET).update(parts[0]).digest();
  const supplied = Buffer.from(parts[1], "base64url");
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!/^\d{17,20}$/.test(payload.discordId) || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
function clearCookie(res) {
  res.setHeader("Set-Cookie", "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
}
function htmlPage(title, message) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' +
    escapeHtml(title) + '</title></head><body style="font-family:system-ui,sans-serif;max-width:680px;margin:12vh auto;padding:24px;line-height:1.6">' +
    "<h1>" + escapeHtml(title) + "</h1><p>" + message + "</p><p>You can close this page and return to Discord.</p></body></html>";
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
  const url = new URL("/login", REDIRECT_URI);
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
function hasRole(interaction) {
  const roles = interaction.member && interaction.member.roles;
  if (Array.isArray(roles)) return roles.includes(VERIFY_ROLE_ID);
  return Boolean(roles && roles.cache && roles.cache.has(VERIFY_ROLE_ID));
}
async function showVerify(interaction) {
  return interaction.reply({ embeds: [verifyEmbed()], components: [verifyRow(interaction.user.id)], ephemeral: true });
}

client.once("ready", async () => {
  console.log("Discord bot logged in as " + client.user.tag);
  client.user.setActivity("Discord verification", { type: ActivityType.Watching });
  try {
    const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);
    await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commandData });
    console.log("Registered " + commandData.length + " slash commands in guild " + GUILD_ID);
  } catch (error) {
    console.error("Slash command registration failed: " + error.message);
  }
});

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;
  try {
    if (!interaction.inGuild()) {
      return interaction.reply({ content: "Use this command inside the configured Discord server.", ephemeral: true });
    }
    if (interaction.commandName === "verify") return showVerify(interaction);
    if (!hasRole(interaction)) return showVerify(interaction);

    if (interaction.commandName === "ping") {
      const started = Date.now();
      await interaction.reply({ content: "🏓 Pong! API latency: " + Math.round(client.ws.ping) + "ms", ephemeral: true });
      return;
    }
    if (interaction.commandName === "help") {
      const embed = new EmbedBuilder().setColor(0x5865F2).setTitle("🤖 Bot commands")
        .setDescription("All commands except /verify require the verification role.")
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
app.get("/login", (req, res) => {
  const discordId = req.query.discord_id;
  if (typeof discordId !== "string" || !/^\d{17,20}$/.test(discordId)) {
    return res.status(400).type("html").send(htmlPage("Invalid verification link", "Return to Discord and click Verify in the bot's message."));
  }
  const state = signState({ discordId, nonce: crypto.randomBytes(24).toString("hex"), exp: Date.now() + 600000 });
  res.setHeader("Set-Cookie", "oauth_state=" + encodeURIComponent(state) + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600");
  const authorizeUrl = new URL("https://discord.com/oauth2/authorize");
  authorizeUrl.search = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: "code", scope: "identify", state
  }).toString();
  return res.redirect(302, authorizeUrl.toString());
});

app.get("/auth/callback", async (req, res) => {
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
    await axios.put(
      "https://discord.com/api/v10/guilds/" + GUILD_ID + "/members/" + user.id + "/roles/" + VERIFY_ROLE_ID,
      null,
      { headers: { Authorization: "Bot " + DISCORD_TOKEN }, timeout: 10000 }
    );
    return res.status(200).type("html").send(htmlPage(
      "Verification complete",
      "Successfully authorized as <strong>" + escapeHtml(user.global_name || user.username) +
      "</strong>. Your verification role has been added. Return to Discord and retry your command."
    ));
  } catch (err) {
    const status = err.response && err.response.status;
    console.error("OAuth/role assignment failed: " + (status || err.message));
    const message = status === 404
      ? "Your account was not found in the configured server. Join the server first, then verify again."
      : status === 403
        ? "The bot could not assign the verification role. Give the bot Manage Roles permission and move its highest role above the verification role."
        : "Discord authorization or role assignment failed. Return to Discord and try again.";
    return res.status(502).type("html").send(htmlPage("Verification could not be completed", message));
  }
});
app.use((_req, res) => res.status(404).type("text").send("Not found"));
app.listen(PORT, "0.0.0.0", () => console.log("Auth Bot web server listening on port " + PORT));
client.login(DISCORD_TOKEN).catch(error => {
  console.error("Discord bot login failed: " + error.message);
  process.exit(1);
});
