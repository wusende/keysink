# assets

`social-preview.png` — 1200×630 GitHub social preview card, generated from
`social-preview.html` (source of truth; edit the HTML, don't retouch the PNG).

Regenerate:

```bash
cd assets
chromium --headless --no-sandbox --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1200,630 \
  --screenshot=raw.png social-preview.html
convert raw.png -resize 1200x630 social-preview.png && rm raw.png
```

Upload it under Settings → Social preview (GitHub has no API for this).
