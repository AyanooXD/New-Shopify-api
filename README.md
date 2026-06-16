# Shopify Card Checker API - Railway Ready

## Files
- `api.py` → Main Flask application
- `requirements.txt`
- `Procfile`

## How to Deploy on Railway

1. Create new project on Railway
2. Upload these 3 files (or push to GitHub)
3. Railway will automatically detect Python + Procfile
4. Deploy

## Endpoint

`GET /shopify?site=https://example.myshopify.com&cc=4242424242424242|12|2028|123&proxy=optional`

## Notes
- This is a heavy async Flask app.
- For better performance on Hobby plan, keep concurrency low.
- Uses aiohttp for requests.
