#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Simple, idempotent SEO maintenance for a single-page static site.
# Only commits when it actually changes SEO-relevant files.

PUBLIC_DIR="$ROOT_DIR/public"
REPORT_DIR="$ROOT_DIR/reports"
mkdir -p "$REPORT_DIR"

ts="$(date -u +%Y%m%d-%H%M%S)-utc"
report="$REPORT_DIR/seo-${ts}.md"

lock_dir="/tmp/science-legal-seo.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
  echo "Another SEO maintenance run is in progress; exiting." >> "$report"
  exit 0
fi
trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT

echo "# SEO maintenance report" > "$report"
echo >> "$report"
echo "- timestamp_utc: ${ts}" >> "$report"
echo "- repo: $(git remote get-url origin 2>/dev/null || echo none)" >> "$report"
echo "- head: $(git rev-parse --short HEAD 2>/dev/null || echo none)" >> "$report"
echo >> "$report"

# Ensure robots.txt and sitemap.xml exist (should be committed, but keep it self-healing).
if [[ ! -f "$PUBLIC_DIR/robots.txt" ]]; then
  cat > "$PUBLIC_DIR/robots.txt" <<'EOF'
User-agent: *
Allow: /

Sitemap: https://science.legal/sitemap.xml
EOF
  echo "- created: public/robots.txt" >> "$report"
fi

if [[ ! -f "$PUBLIC_DIR/sitemap.xml" ]]; then
  cat > "$PUBLIC_DIR/sitemap.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://science.legal/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
EOF
  echo "- created: public/sitemap.xml" >> "$report"
fi

# Stage only the SEO-relevant files; do not stage reports.
git add public/index.html public/robots.txt public/sitemap.xml 2>/dev/null || true

if git diff --cached --quiet; then
  echo >> "$report"
  echo "- changes: none" >> "$report"
  exit 0
fi

echo >> "$report"
echo "- changes: yes" >> "$report"
echo >> "$report"
echo "## Diff (staged)" >> "$report"
echo '```' >> "$report"
git diff --cached --stat >> "$report"
echo '```' >> "$report"

git commit -m "chore(seo): maintenance (${ts})"

# Push may fail in restricted environments; caller can rerun with appropriate network perms.
git push
