# CheckVault

Photograph checks, save them encrypted to your own Backblaze B2 bucket (free 10 GB, no credit card), search them later.

## What it does
- Camera capture (front and back) from your phone browser, or upload existing scans
- Images and records are encrypted with your key **before** upload, then S3 encrypts them again at rest
- Nothing is public: images only load through the logged-in app
- Search by payee, amount, check number, or memo

## Setup
```bash
pip install -r requirements.txt

# set up two-factor: prints a QR code to scan with an authenticator app
python setup_2fa.py
export TOTP_SECRET="<secret it printed>"

# generate an encryption key ONCE and back it up somewhere safe (lose it = lose your checks)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

export ENCRYPTION_KEY="<key from above>"
export APP_PASSWORD="<long random password>"
export APP_USER="me"                 # optional
export S3_ENDPOINT="https://s3.us-east-005.backblazeb2.com"   # shown on your B2 bucket page
export S3_BUCKET="your-private-bucket"   # leave unset to test with a local ./data folder
export AWS_ACCESS_KEY_ID="<B2 keyID>"
export AWS_SECRET_ACCESS_KEY="<B2 applicationKey>"
export AWS_REGION="us-east-005"      # the region part of your endpoint

uvicorn main:app --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000 and sign in.

## Backblaze B2 checklist (no credit card needed)
1. Sign up at backblaze.com and create a B2 bucket set to **Private**
2. Turn on the bucket's default encryption
3. Create an Application Key limited to that one bucket, and use its keyID and applicationKey above
4. Free limits (check Backblaze's pricing page): 10 GB storage and about 1 GB of downloads per day. The app
   stores shrunken images plus tiny thumbnails so normal use stays far under that.

## Using it from your phone
Sign-in needs your password plus a 6-digit authenticator code, and the session cookie is only sent over HTTPS (set `COOKIE_SECURE=0` only for local http testing). After 5 failed attempts from the same visitor, sign-in locks for 15 minutes. Put the app behind HTTPS
(Cloudflare Tunnel, Tailscale, or a small host with a Let's Encrypt certificate) before
opening it from outside your home network. Never expose plain http.

## Not included yet
OCR to auto-fill fields and a second-copy backup. See next steps in the chat.

## Deploying on Render (free, no card)
1. Put these files in a **private** GitHub repository (upload them in the browser). Never upload passwords or keys.
2. On render.com create a **Web Service** from that repo, instance type **Free**.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"`
5. Add these under **Environment** (type them in on Render's site, not in the code): `APP_PASSWORD`, `ENCRYPTION_KEY`,
   `TOTP_SECRET`, `S3_ENDPOINT`, `S3_BUCKET`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`.
6. Optional: `SESSION_MINUTES` (how long a sign-in lasts, default 5).
7. Free services sleep after about 15 idle minutes, so the first visit can take around 30 seconds.
