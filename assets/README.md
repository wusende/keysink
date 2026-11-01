# assets

`social-preview.html` — source of truth for the 1200×630 GitHub social preview
card. The rendered PNG is **not tracked** (GitHub keeps its own copy once you
upload it under Settings → Social preview); regenerate it when you need the file.

Regenerate:

```bash
cd assets
chromium --headless --no-sandbox --disable-gpu --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1200,630 \
  --screenshot=raw.png social-preview.html
convert raw.png -resize 1200x630 social-preview.png && rm raw.png
```

Upload it under Settings → Social preview (GitHub has no API for this).
