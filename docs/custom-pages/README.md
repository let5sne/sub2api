# Custom Image Tool Embed Page

This folder provides a ready-to-host image generation page for Sub2API custom menu iframe integration.

## File

- `image-tool-embed.html`: standalone page (no build step), can be hosted on any static server.

## How to use in Sub2API

1. Host `image-tool-embed.html` on a domain that allows iframe embedding.
2. Open admin settings, add a Custom Menu Item:
   - Name: `Image Studio` (or your preferred label)
   - URL: your hosted page URL
   - Visibility: `user` or `admin`
3. Save settings and open the new menu item.

## Embedded query params

When loaded inside Sub2API custom page, this template can read:

- `user_id`
- `token`
- `theme` (`light` or `dark`)
- `lang`
- `ui_mode`
- `src_host`
- `src_url`

## Endpoint contract expectation

The template sends a `POST` request to your configured endpoint and tries to parse image outputs from common fields:

Current defaults are aligned to this request shape:

```json
{
   "model": "gpt-image-2",
   "prompt": "一只橘猫戴着橙色围巾抱着水獭，温暖插画风格",
   "size": "3840x2160",
   "quality": "high",
   "output_format": "png",
   "response_format": "b64_json",
   "n": 1
}
```

When embedded inside Sub2API, the page may also attach these metadata fields:

```json
{
   "lang": "zh",
   "user_id": 123,
   "context": {
      "ui_mode": "embedded",
      "src_host": "https://your-sub2api-host.example.com",
      "src_url": "https://your-sub2api-host.example.com/custom/xxx"
   }
}
```

- `data[].url`
- `data[].b64_json`
- `images[].url`
- `images[].base64`
- `output[].url`

If your API uses different fields, adjust `collectImages(...)` in `image-tool-embed.html`.

## Security note

- Use HTTPS in production. HTTP is only acceptable for localhost development.
- URL query token is detected but not auto-used; user must click `Use URL Token` manually.
- Preferred approach: pass token via `postMessage`.
   - Child page emits: `SUB2API_EMBED_READY`
   - Parent page can send: `{ type: "SUB2API_EMBED_TOKEN", token: "..." }`
- Only embed this page in trusted first-party domains.
