# Shopify Card Checker API - Railway (Fixed)

## Files
- api.py (Main Flask app)
- requirements.txt
- Procfile

## Deployment
1. Upload to Railway
2. It will use gunicorn automatically via Procfile
3. Endpoint: /shopify?site=...&cc=... 

Note: This uses normal gunicorn workers (suitable for Flask WSGI app).
