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

This repo includes a GitHub Actions workflow that deploys to Cloudflare Pages on every push to `main`.

Required GitHub repository secrets:
- `CLOUDFLARE_API_TOKEN`: Cloudflare API token with `Pages:Edit`.
- `CLOUDFLARE_ACCOUNT_ID`: Cloudflare account id, e.g. `43a1dcc493f6486971c7c6ddff944c12`.

## Custom domain (apex)

To serve `science.legal`, Cloudflare will require a DNS record:
- `CNAME` `science.legal` -> `science-legal.pages.dev` (proxied)
