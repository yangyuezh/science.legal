# science.legal

Static site for `science.legal`, designed for free hosting on Cloudflare Pages via GitHub.

## Local preview

Open `index.html` directly in browser.

## Deploy target

- Cloudflare Pages (Free)
- Framework preset: `None`
- Build command: *(leave empty)*
- Build output directory: `/`

## GitHub -> Cloudflare Pages auto-deploy

Use Cloudflare Pages built-in GitHub integration (recommended). It does not require sharing any API token with this repo.

## Custom domain (apex)

To serve `science.legal`, Cloudflare will require a DNS record:
- `CNAME` `science.legal` -> `science-legal.pages.dev` (proxied)
