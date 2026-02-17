# science.legal

Static site for `science.legal`, configured to deploy as an assets-only Cloudflare Worker (so `wrangler deploy` works).

## Local preview

Open `public/index.html` directly in browser.

## Deploy target

- Cloudflare Workers (assets-only)
- Deploy command: `npx wrangler deploy` (reads `wrangler.jsonc`)

## GitHub -> Cloudflare auto-deploy

Use Cloudflare's Git integration to run `npx wrangler deploy` on commits.

## ORCID login integration

This Worker includes ORCID OAuth endpoints:
- `/auth/orcid/login`
- `/auth/orcid/callback`
- `/auth/orcid/logout`
- `/api/me`
- `/orcid.html`

Additional sign-in entry endpoints:
- `/auth/wos/login` (Web of Science entry; OAuth if configured, else portal redirect)
- `/auth/wos/callback`
- `/auth/wos/logout`
- `/api/wos/me`
- `/wos.html`
- `/auth/altmetric/login` (Altmetric portal entry)
- `/auth/altmetric/logout`
- `/api/altmetric/me`
- `/altmetric.html`

Set these Cloudflare Worker environment variables:
- `ORCID_CLIENT_ID`
- `ORCID_CLIENT_SECRET`
- `SESSION_SECRET` (long random string used for cookie signing)
- `ORCID_REDIRECT_URI` (optional; defaults to `https://<your-domain>/auth/orcid/callback`)
- `ORCID_BASE_URL` (optional; default `https://orcid.org`; use `https://sandbox.orcid.org` for sandbox)

In ORCID application settings, register callback URL:
- `https://science.legal/auth/orcid/callback`

Optional Web of Science OAuth variables (for on-site verified WOS status):
- `WOS_CLIENT_ID`
- `WOS_CLIENT_SECRET`
- `WOS_AUTHORIZE_URL`
- `WOS_TOKEN_URL`
- `WOS_REDIRECT_URI` (optional; defaults to `https://<your-domain>/auth/wos/callback`)
- `WOS_SCOPE` (optional; default `openid profile email`)
- `WOS_PORTAL_URL` (optional; default `https://www.webofscience.com`)

Optional Altmetric variables:
- `ALTMETRIC_PORTAL_URL` (optional; default `https://www.altmetric.com/explorer/login`)
- `ALTMETRIC_API_KEY` (optional; enables API-connected status indication)

## Custom domain (apex)

Attach `science.legal` in the Cloudflare dashboard after the Worker deploys successfully.
