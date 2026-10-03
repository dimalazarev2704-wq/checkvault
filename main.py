import hashlib, hmac, io, json, math, os, secrets, time, urllib.parse, urllib.request, uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
import pyotp
from PIL import Image, ImageOps
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer

USER = os.environ.get("APP_USER", "me")
PASSWORD = os.environ["APP_PASSWORD"]
fernet = Fernet(os.environ["ENCRYPTION_KEY"])
BUCKET = os.environ.get("S3_BUCKET")  # unset = local folder mode (for testing)
DATA = Path(os.environ.get("DATA_DIR", "data"))
MAX_BYTES = 10 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 50_000_000  # refuse absurdly large images (protects a small free server's memory)

if BUCKET:
    import boto3
    from botocore.config import Config
    s3 = boto3.client("s3", endpoint_url=os.environ.get("S3_ENDPOINT"),
                      config=Config(request_checksum_calculation="when_required",
                                    response_checksum_validation="when_required",
                                    retries={"max_attempts": 4, "mode": "standard"}))

    def _no_expect(request, **kwargs):
        # Backblaze answers "Expect: 100-continue" in a way newer Python/urllib3 cannot parse (BadStatusLine).
        try:
            request.headers.pop("Expect", None)
        except Exception:
            pass

    s3.meta.events.register("before-send.s3", _no_expect)
else:
    DATA.mkdir(exist_ok=True)


def put(key, blob):
    if BUCKET:
        try:
            s3.put_object(Bucket=BUCKET, Key=key, Body=blob)
        except Exception:
            raise HTTPException(502, "Could not reach cloud storage. Please try again.")
    else:
        p = DATA / key
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)


def get(key):
    try:
        if BUCKET:
            return s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
        return (DATA / key).read_bytes()
    except FileNotFoundError:
        raise HTTPException(404, "Not found")
    except Exception as e:
        if getattr(e, "response", {}).get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            raise HTTPException(404, "Not found")
        raise HTTPException(502, "Storage error")


def remove(key):
    if BUCKET:
        try:
            s3.delete_object(Bucket=BUCKET, Key=key)
        except Exception:
            raise HTTPException(502, "Could not reach cloud storage. Please try again.")
    else:
        (DATA / key).unlink(missing_ok=True)


def keys(prefix):
    if BUCKET:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=prefix):
            for o in page.get("Contents", []):
                yield o["Key"]
    else:
        for p in (DATA / prefix).glob("*"):
            yield f"{prefix}{p.name}"


TOTP = pyotp.TOTP(os.environ["TOTP_SECRET"]) if os.environ.get("TOTP_SECRET") else None  # optional backup
TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_USERS = {}  # name -> Telegram id, from TELEGRAM_USERS="me:111,mom:222,dad:333"
for _part in os.environ.get("TELEGRAM_USERS", "").split(","):
    if ":" in _part:
        _n, _i = _part.rsplit(":", 1)
        if _n.strip() and _i.strip().isdigit():
            TG_USERS[_n.strip().lower()] = _i.strip()
TG_SECRET = hashlib.sha256(b"tgwebhook:" + os.environ["ENCRYPTION_KEY"].encode()).hexdigest()[:48]
PUBLIC_URL = (os.environ.get("PUBLIC_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "").rstrip("/")
ASK_SECONDS = 120  # how long a Telegram approval request stays valid
reqs = {}   # request id -> approval request (memory only, short-lived)
asked = {}  # person -> times they were messaged recently (flood guard)


def tg_call(method, payload):
    req = urllib.request.Request(f"https://api.telegram.org/bot{TG_TOKEN}/{method}", json.dumps(payload).encode(),
                                 {"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except Exception:
        return None  # never print the error: it could contain the bot token


def tg_close(r, text):
    """Replace a request's Telegram message with a final note, which also removes its buttons."""
    if r.get("chat") and r.get("msg"):
        tg_call("editMessageText", {"chat_id": r["chat"], "message_id": r["msg"], "text": text})
        r["msg"] = None


def valid_user(username):
    return username.strip().lower() in TG_USERS or secrets.compare_digest(username.encode(), USER.encode())


def stamp():
    return datetime.now(timezone.utc).strftime("%b %d, %H:%M UTC")
signer = URLSafeTimedSerializer(hashlib.sha256(b"session:" + os.environ["ENCRYPTION_KEY"].encode()).hexdigest())
SESSION_SECONDS = int(float(os.environ.get("SESSION_MINUTES", "5")) * 60)
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"  # set 0 only for local http testing
MAX_FAILS, WINDOW = 5, 15 * 60
fails, last_code = {}, [""]  # failure times per visitor address; last accepted code (blocks reuse)
GLOBAL_MAX = 25  # failures from everyone combined, stops guessing from many addresses


def ip_of(request):
    return request.client.host if request.client else "unknown"


def locked(ip):
    now = time.time()
    for k in list(fails):
        fails[k] = [t for t in fails[k] if now - t < WINDOW]
        if not fails[k]:
            del fails[k]
    return len(fails.get(ip, [])) >= MAX_FAILS or sum(len(v) for v in fails.values()) >= GLOBAL_MAX


def auth(request: Request):
    path = request.url.path
    if path in ("/login", "/login/people", "/login/ask", "/login/status", "/telegram/webhook"):
        return
    try:
        signer.loads(request.cookies.get("session", ""), max_age=SESSION_SECONDS)
        return
    except BadSignature:
        pass
    if path.startswith("/api"):
        raise HTTPException(401, "Sign in required")
    raise HTTPException(307, headers={"Location": "/login"})


app = FastAPI(dependencies=[Depends(auth)], docs_url=None, redoc_url=None)


@app.exception_handler(Exception)
async def unexpected_error(request, exc):
    return JSONResponse({"detail": "Something went wrong on the server. Please try again."}, status_code=500)


@app.middleware("http")
async def security_headers(request, call_next):
    size = request.headers.get("content-length", "")
    if size.isdigit() and int(size) > 25 * 1024 * 1024:
        return JSONResponse({"detail": "Upload too large"}, status_code=413)
    r = await call_next(request)
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
    return r


@app.get("/login")
def login_page():
    return FileResponse(Path(__file__).parent / "login.html")


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""), code: str = Form("")):
    ip = ip_of(request)
    if locked(ip):
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    code = code.replace(" ", "")
    user_ok = valid_user(username)
    pass_ok = secrets.compare_digest(password.encode(), PASSWORD.encode())
    code_ok = bool(TOTP) and TOTP.verify(code, valid_window=1) and code != last_code[0]
    if not (user_ok and pass_ok and code_ok):
        fails.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "Wrong username, password, or code")
    fails.pop(ip, None)
    last_code[0] = code
    return start_session()


def start_session(extra=None):
    resp = JSONResponse({"ok": True, **(extra or {})})
    resp.set_cookie("session", signer.dumps("ok"), max_age=SESSION_SECONDS,
                    httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return resp


@app.get("/login/people")
def people():
    return {"people": list(TG_USERS) if TG_TOKEN else []}


@app.post("/login/ask")
def ask(request: Request, username: str = Form(""), password: str = Form(""), who: str = Form("")):
    ip = ip_of(request)
    if locked(ip):
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    if not TG_TOKEN:
        raise HTTPException(400, "Telegram sign-in is not set up.")
    who, now = who.strip().lower(), time.time()
    for k in [k for k, v in reqs.items() if v["exp"] < now - 60]:
        del reqs[k]
    rid, poll = secrets.token_hex(16), secrets.token_urlsafe(24)
    r = {"poll": poll, "chat": None, "msg": None, "who": who, "ip": ip, "status": "pending", "exp": now + ASK_SECONDS}
    reqs[rid] = r
    if not (valid_user(username) and secrets.compare_digest(password.encode(), PASSWORD.encode()) and who in TG_USERS):
        fails.setdefault(ip, []).append(now)  # wrong details look exactly like right ones to the visitor
        return {"poll": poll}
    asked[who] = [t for t in asked.get(who, []) if now - t < 600]
    if len(asked[who]) >= 3:  # at most 3 messages per person per 10 minutes
        return {"poll": poll}
    asked[who].append(now)
    sent = tg_call("sendMessage", {
        "chat_id": TG_USERS[who],
        "text": f"Someone is trying to sign in to CheckVault.\n\nTime: {stamp()}\nFrom: {ip}\n\n"
                "Tap It's me only if you, or someone you are expecting, is signing in right now.",
        "reply_markup": {"inline_keyboard": [[{"text": "\u2705 It's me", "callback_data": "y:" + rid},
                                              {"text": "\U0001F6AB It's not me", "callback_data": "n:" + rid}]]}})
    if sent and sent.get("ok"):
        r["chat"], r["msg"] = TG_USERS[who], sent["result"]["message_id"]
    return {"poll": poll}


@app.post("/login/status")
def status(poll: str = Form(""), cancel: str = Form("")):
    now = time.time()
    for rid, r in reqs.items():
        if secrets.compare_digest(poll.encode(), r["poll"].encode()):
            break
    else:
        return {"status": "expired"}
    if r["status"] == "pending" and cancel == "1":
        r["status"] = "expired"
        tg_close(r, "Cancelled by the person signing in.")
    if r["status"] == "pending" and now > r["exp"]:
        r["status"] = "expired"
        tg_close(r, "Expired. Nobody answered in time.")
    if r["status"] == "approved":
        del reqs[rid]  # single use: the session is handed out exactly once
        return start_session({"status": "approved"})
    return {"status": r["status"]}


@app.post("/telegram/webhook")
def telegram_webhook(request: Request, update: dict = Body(...)):
    if not TG_TOKEN or not hmac.compare_digest(request.headers.get("x-telegram-bot-api-secret-token", ""), TG_SECRET):
        raise HTTPException(403, "Forbidden")
    cb = update.get("callback_query")
    if not cb:
        return {"ok": True}
    act, _, rid = str(cb.get("data", "")).partition(":")
    r, uid, msg = reqs.get(rid), str((cb.get("from") or {}).get("id", "")), cb.get("message") or {}
    usable = r and act in ("y", "n") and r["chat"] and uid == r["chat"] and r["status"] == "pending" and time.time() < r["exp"]
    if not usable:  # already used, expired, or from the wrong person
        tg_call("answerCallbackQuery", {"callback_query_id": cb["id"], "show_alert": True,
                                        "text": "This button was already used or has expired."})
        if msg.get("message_id") and (msg.get("chat") or {}).get("id"):
            tg_call("editMessageReplyMarkup", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                               "reply_markup": {"inline_keyboard": []}})
        return {"ok": True}
    if act == "y":
        r["status"] = "approved"
        tg_call("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Approved"})
        tg_close(r, f"Approved at {stamp()}. This button can't be used again.")
    else:
        r["status"] = "denied"
        fails.setdefault(r["ip"], []).extend([time.time()] * MAX_FAILS)  # block that address for 15 minutes
        tg_call("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Denied and logged"})
        tg_close(r, f"Denied at {stamp()}. The attempt from {r['ip']} was logged and blocked for 15 minutes.")
        for chat in TG_USERS.values():
            if chat != r["chat"]:
                tg_call("sendMessage", {"chat_id": chat, "text": f"Warning: {r['who'].title()} tapped It's not me on a "
                        f"CheckVault sign-in.\nTime: {stamp()}\nFrom: {r['ip']}\nThat address is blocked for 15 minutes."})
    return {"ok": True}


@app.on_event("startup")
def register_webhook():
    if TG_TOKEN and PUBLIC_URL:
        tg_call("setWebhook", {"url": f"{PUBLIC_URL}/telegram/webhook", "secret_token": TG_SECRET,
                               "allowed_updates": ["callback_query"], "drop_pending_updates": True})


@app.post("/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


def check_id(cid):
    try:
        return str(uuid.UUID(cid))
    except ValueError:
        raise HTTPException(400, "Bad id")


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "index.html")


INDEX = "index.enc"  # one encrypted file holding every check's details (1 read per page load)


def load_index():
    try:
        return json.loads(fernet.decrypt(get(INDEX)))
    except HTTPException as e:
        if e.status_code == 404:
            return []
        raise


def save_index(recs):
    put(INDEX, fernet.encrypt(json.dumps(recs).encode()))


def open_image(blob):
    try:
        img = Image.open(io.BytesIO(blob))
        img.draft("RGB", (1600, 1600))  # JPEGs decode at reduced size, saving memory
        return ImageOps.exif_transpose(img).convert("RGB")
    except Exception:
        raise HTTPException(400, "That file is not a valid image")


def jpeg(img, size, quality):
    img = img.copy()
    img.thumbnail((size, size))
    out = io.BytesIO()
    img.save(out, "JPEG", quality=quality, optimize=True)  # re-encoding also strips GPS/EXIF data
    return out.getvalue()


@app.post("/api/checks")
async def add_check(
    date: str = Form(...), payee: str = Form(...), amount: float = Form(...),
    check_number: str = Form(""), memo: str = Form(""),
    front: UploadFile = File(...), back: UploadFile = File(None),
):
    if not (math.isfinite(amount) and 0 <= amount < 1e9):
        raise HTTPException(400, "Amount must be a normal positive number")
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Date must look like 2026-09-29")
    payee, check_number, memo = payee.strip()[:100], check_number.strip()[:30], memo.strip()[:200]
    if not payee:
        raise HTTPException(400, "Payee is required")
    cid = str(uuid.uuid4())
    parts = {}
    for side, f in (("front", front), ("back", back)):
        if f is None:
            continue
        blob = await f.read()
        if len(blob) > MAX_BYTES:
            raise HTTPException(413, "Image over 10 MB")
        img = open_image(blob)
        parts[side] = jpeg(img, 1600, 80)
        if side == "front":
            parts["thumb"] = jpeg(img, 240, 70)
    for name, data in parts.items():
        put(f"images/{cid}-{name}.enc", fernet.encrypt(data))
    rec = dict(id=cid, date=date, payee=payee.strip(), amount=round(amount, 2),
               check_number=check_number.strip(), memo=memo.strip(),
               has_back="back" in parts, created=datetime.now(timezone.utc).isoformat())
    recs = load_index()
    recs.append(rec)
    save_index(recs)
    return rec


@app.get("/api/checks")
def list_checks():
    return sorted(load_index(), key=lambda r: (r["date"], r["created"]), reverse=True)


@app.get("/api/checks/{cid}/{side}")
def image(cid: str, side: str):
    if side not in ("front", "back", "thumb"):
        raise HTTPException(400, "Bad side")
    blob = fernet.decrypt(get(f"images/{check_id(cid)}-{side}.enc"))
    return Response(blob, media_type="image/jpeg", headers={"Cache-Control": "no-store"})


@app.delete("/api/checks/{cid}")
def delete(cid: str):
    cid = check_id(cid)
    save_index([r for r in load_index() if r["id"] != cid])
    for name in ("front", "back", "thumb"):
        remove(f"images/{cid}-{name}.enc")
    return {"deleted": cid}


@app.delete("/api/checks/{cid}/back")
def delete_back(cid: str):
    cid = check_id(cid)
    recs = load_index()
    for r in recs:
        if r["id"] == cid:
            r["has_back"] = False
            break
    else:
        raise HTTPException(404, "Not found")
    save_index(recs)
    remove(f"images/{cid}-back.enc")
    return {"deleted": "back"}
