# science.legal

Static site for `science.legal`, configured to deploy as an assets-only Cloudflare Worker (so `wrangler deploy` works).

## Local preview

Open `public/index.html` directly in browser.

## Deploy target

- Cloudflare Workers (assets-only)
- Deploy command: `npx wrangler deploy` (reads `wrangler.jsonc`)

## GitHub -> Cloudflare auto-deploy

Use Cloudflare's Git integration to run `npx wrangler deploy` on commits.

## Custom domain (apex)

Attach `science.legal` in the Cloudflare dashboard after the Worker deploys successfully.
