require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("node:crypto");

const app = express();
app.disable("x-powered-by");

const PORT = Number(process.env.PORT) || 3000;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

const missing = [
  ["CLIENT_ID", CLIENT_ID],
  ["CLIENT_SECRET", CLIENT_SECRET],
  ["REDIRECT_URI", REDIRECT_URI],
].filter(([, value]) => !value);

if (missing.length) {
  console.error(`Missing required environment variables: ${missing.map(([key]) => key).join(", ")}`);
  process.exit(1);
}

let redirectUrl;
try {
  redirectUrl = new URL(REDIRECT_URI);
  if (redirectUrl.protocol !== "https:" && redirectUrl.hostname !== "localhost") {
    throw new Error("REDIRECT_URI must use HTTPS (except on localhost).");
  }
} catch (error) {
  console.error("Invalid REDIRECT_URI:", error.message);
  process.exit(1);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";
  const prefix = `${name}=`;
  const item = cookieHeader.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : null;
}

function clearStateCookie(res) {
  res.setHeader("Set-Cookie", "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
}

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Discord Verification</title></head>
<body style="font-family:system-ui,sans-serif;max-width:640px;margin:12vh auto;padding:24px;line-height:1.6">
  <h1>Discord verification</h1>
  <p>Sign in with Discord to confirm your Discord identity. This app requests only the basic identity scope and does not ask for your Discord password.</p>
  <p><a href="/login">Continue with Discord</a></p>
</body></html>`);
});

app.get("/health", (_req, res) => res.status(200).json({ status: "ok" }));

app.get("/login", (_req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  res.setHeader("Set-Cookie", `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);

  const authorizeUrl = new URL("https://discord.com/oauth2/authorize");
  authorizeUrl.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify",
    state,
  }).toString();

  return res.redirect(302, authorizeUrl.toString());
});

app.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    clearStateCookie(res);
    return res.status(400).type("html").send("<h1>Discord sign-in was cancelled</h1><p>You can close this page and try again if you intended to sign in.</p>");
  }

  const cookieState = getCookie(req, "oauth_state");
  clearStateCookie(res);

  if (typeof state !== "string" || !cookieState || state !== cookieState) {
    return res.status(400).type("html").send("<h1>Verification failed</h1><p>The sign-in state was invalid or expired. Please return to the app and try again.</p>");
  }

  if (typeof code !== "string" || !code) {
    return res.status(400).type("html").send("<h1>Verification failed</h1><p>Discord did not return an authorization code. Please try again.</p>");
  }

  try {
    const tokenResponse = await axios.post(
      "https://discord.com/api/v10/oauth2/token",
      new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
      }).toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 10000,
      }
    );

    const accessToken = tokenResponse.data.access_token;
    if (!accessToken) {
      throw new Error("Discord did not return an access token.");
    }

    const userResponse = await axios.get("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 10000,
    });

    const user = userResponse.data;
    if (!user || !user.id || !user.username) {
      throw new Error("Discord returned an incomplete user profile.");
    }

    // Identity-only verification: no token is stored or exposed to the browser.
    return res.status(200).type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verification complete</title></head>
<body style="font-family:system-ui,sans-serif;max-width:640px;margin:12vh auto;padding:24px;line-height:1.6">
  <h1>Discord identity verified</h1>
  <p>Successfully signed in as <strong>${escapeHtml(user.global_name || user.username)}</strong>.</p>
  <p>Your Discord account ID: <code>${escapeHtml(user.id)}</code></p>
  <p>You can close this page. No access token has been saved.</p>
</body></html>`);
  } catch (err) {
    const status = err.response?.status;
    console.error("Discord OAuth callback failed:", status ? `HTTP ${status}` : err.message);
    return res.status(502).type("html").send("<h1>Verification could not be completed</h1><p>Discord sign-in failed or expired. Please return to the app and try again.</p>");
  }
});

app.use((_req, res) => res.status(404).type("text").send("Not found"));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Auth bot web server listening on port ${PORT}`);
});
