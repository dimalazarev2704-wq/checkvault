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


## Telegram approval button (for you, mom and dad)

On the six-digit step there is a **Use Telegram instead** button. You pick who to ask (Me, Mom, Dad), and the bot sends that person a message with two buttons, **It's me** and **It's not me**. No code is ever shown in Telegram. Each message works once and expires after 2 minutes.

1. In Telegram, message **@BotFather**, send `/newbot`, pick a name and a username ending in `bot`. Copy the token it gives you (treat it like a password).
2. Everyone on the list (you, mom, dad) opens the new bot and taps **Start** once. A bot cannot message someone who has not done this.
3. Each person finds their Telegram ID by messaging **@userinfobot** and reading the number it replies with.
4. In Render, add two environment variables:
   - `TELEGRAM_BOT_TOKEN` = the token from step 1
   - `TELEGRAM_USERS` = `me:111111111,mom:222222222,dad:333333333` (a name, a colon, the Telegram ID; people separated by commas)
5. Redeploy. The site connects the bot to itself on startup (Render supplies the site address automatically; if you use another host, set `PUBLIC_URL` to your site's https address).

Only people on that list can approve, and only their own message. Tapping **It's not me** blocks that visitor's address for 15 minutes and warns the others in Telegram. The normal six-digit code from your authenticator app keeps working, and needs `TOTP_SECRET` to stay set in Render.


## Blocked devices in Telegram

Send `/timeouts` to the bot (only the people on `TELEGRAM_USERS` get an answer). It lists every **device** that is timed out for 15 minutes, every **whole network** that is timed out, and every device banned for good. Each entry shows a **code**, an address, and for devices what kind of device it was (for example "Safari on iPhone").

- **Each browser is its own device.** The first time a browser opens the site it is given a private random id (a cookie), so two phones on the same Wi-Fi are told apart and get different codes. One device's wrong tries only time out that device.
- **A device is timed out after 5 wrong tries** in 15 minutes. **Unblock** lifts it at once. **Ban forever** asks you to confirm, then blocks that one device from the whole site until someone presses **Unban**. Bans are saved (encrypted) in your Backblaze bucket, so they survive restarts.
- **A whole network is timed out after 20 wrong tries** from all devices on it combined, so someone who keeps throwing their cookie away can't dodge the limit. A network can be unblocked but not banned.
- **Clear all lockouts** appears if too many failures from all devices together have locked everyone out.
- The blocked device's own screen shows the **address and code**, and the bot's list shows the same code, so you can match them. The code is made with your site's secret, so it can't be faked.
- Everyone else on the list is told when someone bans, unbans or clears.

Honest limits: the id lives in the browser, so clearing cookies, a private window, or another browser counts as a new device. A banned device that does this is not banned any more, but it has to start over at 5 wrong tries and still counts toward its network's 20.

**How the address is worked out:** Render does not clean the `X-Forwarded-For` header, so anyone can write a fake one there. The site uses the Cloudflare headers instead (`cf-connecting-ip`, then `true-client-ip`), which visitors can't fake. After a deploy, the Render Logs show one line, `Visitor address comes from: cf-connecting-ip`. If it says `connection` instead, addresses can be faked, so tell the site's builder. An IPv6 visitor counts as their whole /64 network, shown like `2606:4700:abcd:12::/64`.
