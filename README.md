# Discord OAuth2 Auth Bot

A Discord.js bot with a small Express verification website. Users authorize through Discord OAuth2 once; the bot stores their Discord user ID in PostgreSQL and gates its utility slash commands until authorization is complete. No Discord password is collected and no server role is added.

## Features

- Discord OAuth2 authorization with a signed, short-lived state value and an HttpOnly SameSite cookie.
- Checks that the Discord account authorizing matches the account that requested verification.
- Persistent verification records in PostgreSQL, shared across servers where the bot is installed.
- Responsive verification result page and safe HTML escaping.
- Basic security headers, no-cache responses, and per-IP throttling on OAuth endpoints.
- `/health` endpoint for Render health checks.
- Graceful shutdown on SIGTERM/SIGINT and startup diagnostics.
- Commands: `/verify`, `/help`, `/ping`, `/userinfo`, `/serverinfo`, `/avatar`, `/botinfo`, `/uptime`.

## Discord Developer Portal

1. Create or open your Discord application and add a bot user.
2. Under **OAuth2 → General**, add the exact callback URL:
   `https://YOUR-RENDER-SERVICE.onrender.com/auth/callback`
3. Copy the Application ID, OAuth2 Client Secret, and bot token into Render environment variables.
4. Invite the bot to your servers with the `bot` and `applications.commands` scopes. Grant only the permissions it needs.

## Render deployment

- **Runtime:** Node
- **Build command:** `npm install`
- **Start command:** `npm start`
- **Health check path:** `/health`
- **Node version:** Node.js 20 or newer

Set these environment variables in Render (never commit real secrets):

| Variable | Required | Description |
| --- | --- | --- |
| `CLIENT_ID` | Yes | Discord Application ID |
| `CLIENT_SECRET` | Yes | OAuth2 Client Secret |
| `DISCORD_TOKEN` | Yes | Bot token |
| `REDIRECT_URI` | Yes | Exact HTTPS callback URL ending in `/auth/callback` |
| `PUBLIC_URL` | Recommended | Public website origin only, e.g. `https://your-service.onrender.com` (no path). Must use the same host as `REDIRECT_URI`. |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `DATABASE_SSL` | Provider-dependent | Set to `true` only if your PostgreSQL provider requires TLS configuration |
| `STATE_SECRET` | Recommended | Long random secret used to sign OAuth state; if omitted, the OAuth client secret is used |

The OAuth redirect URI must exactly match the URL registered in the Discord Developer Portal. Set `PUBLIC_URL` to the exact public Render service origin so the Verify button opens the deployed `/login` route. Both URLs must use the same host. Use a PostgreSQL database that persists data across deploys; the database table is created automatically at startup.

## Authorization behavior

Users run any utility command. If they have not verified, the bot replies privately with a **Verify with Discord** button. After authorizing the same Discord account in the browser, they return to Discord and retry the command. Verification is account-wide and does not grant a role or bypass any server's own permissions.

## Security notes

- Never publish `.env`, bot tokens, client secrets, database URLs, or OAuth tokens.
- Keep `STATE_SECRET` stable between deploys; rotating it invalidates in-progress OAuth attempts.
- Only the `identify` OAuth scope is requested. The bot does not ask for passwords.
- The built-in rate limiter is process-local. If you scale the service to multiple instances, use a shared rate-limit store.
- Verification means the user authorized the app to identify their Discord account; it is not proof of age, identity, or trustworthiness.
