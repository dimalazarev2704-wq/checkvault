import hashlib, hmac, io, ipaddress, json, math, os, re, secrets, threading, time, urllib.parse, urllib.request, uuid
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from cryptography.fernet import Fernet
import pyotp
from PIL import Image, ImageOps
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from itsdangerous import BadSignature, URLSafeSerializer, URLSafeTimedSerializer

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
        except Exception as e:
            print("STORAGE ERROR (upload):", type(e).__name__, str(e)[:400], flush=True)
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
        except Exception as e:
            print("STORAGE ERROR (delete):", type(e).__name__, str(e)[:400], flush=True)
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
        tg_call("editMessageText", {"chat_id": r["chat"], "message_id": r["msg"], "text": text,
                                    "reply_markup": {"inline_keyboard": []}})
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
NET_MAX = 20  # failures from all devices on one network combined, so one device's slips can't lock its neighbours out
net_fails = {}  # network address -> failure times


_ip_logged = set()


def ip_of(request):
    """The visitor's address, as hard to fake as possible.
    Render does not clean X-Forwarded-For, so a visitor can write anything there. The Cloudflare headers are set by the
    edge and cannot be forged, so they come first. An IPv6 visitor counts as their whole /64 network, because one
    household or attacker controls billions of addresses inside it."""
    raw, src = "", "connection"
    for h in ("cf-connecting-ip", "true-client-ip"):
        v = request.headers.get(h, "").split(",")[0].strip()
        if v:
            raw, src = v, h
            break
    if not raw:
        raw = request.client.host if request.client else ""
    if src not in _ip_logged:
        _ip_logged.add(src)
        print("Visitor address comes from:", src, flush=True)
    try:
        a = ipaddress.ip_address(raw)
    except ValueError:
        return "unknown"
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no letters that look like digits
DEV_KEY = hashlib.sha256(b"device:" + os.environ["ENCRYPTION_KEY"].encode()).digest()
BANS = "bans.enc"
banned = {}  # device id -> {"when", "by", "ua", "ip"}: blocked for good until someone unbans it in Telegram
seen = {}    # device id -> {"ua", "ip", "last"}: what each device looked like when it last opened the login page
dsigner = URLSafeSerializer(hashlib.sha256(b"device-cookie:" + os.environ["ENCRYPTION_KEY"].encode()).hexdigest(), salt="device")
DEVICE_COOKIE_SECONDS = 400 * 24 * 3600


def dev_code(key):
    """A short code for a device (or a network): the same everywhere it is shown, and impossible to work out or forge."""
    n = int.from_bytes(hmac.new(DEV_KEY, key.encode(), "sha256").digest()[:8], "big")
    out = ""
    for _ in range(6):
        n, r = divmod(n, len(ALPHA))
        out += ALPHA[r]
    return out


def device_name(ua):
    ua = ua or ""
    os_ = ("iPhone" if "iPhone" in ua else "iPad" if "iPad" in ua else "Android" if "Android" in ua else
           "Windows" if "Windows" in ua else "Mac" if "Macintosh" in ua else "Linux" if "Linux" in ua else "unknown device")
    br = ("Edge" if "Edg/" in ua else "Firefox" if "Firefox" in ua else "Chrome" if ("Chrome" in ua or "CriOS" in ua)
          else "Safari" if "Safari" in ua else "a browser")
    return f"{br} on {os_}"


def read_device(request):
    """The id this browser was given on its first visit, or "" if it has none (or a forged one)."""
    try:
        d = dsigner.loads(request.cookies.get("cvd", ""))
    except BadSignature:
        return ""
    return d if isinstance(d, str) and re.fullmatch(r"[0-9a-f]{32}", d) else ""


def dev_of(request):
    st = getattr(request, "state", None)
    return getattr(st, "device", "") or "x:" + ip_of(request)


def remember_device(dev, ip, ua):
    seen[dev] = {"ua": ua[:300], "ip": ip, "last": time.time()}
    if len(seen) > 500:
        for k in sorted(seen, key=lambda k: seen[k]["last"])[:100]:
            del seen[k]


def note_fail(dev, ip, n=1, network=True):
    now = time.time()
    fails.setdefault(dev, []).extend([now] * n)
    if network:
        net_fails.setdefault(ip, []).extend([now] * n)


def lock_info(dev, ip):
    """(is_locked, seconds_left, reason): this device's own limit, its whole network's limit, and the everyone limit."""
    now = time.time()
    for table in (fails, net_fails):
        for k in list(table):
            table[k] = [t for t in table[k] if now - t < WINDOW]
            if not table[k]:
                del table[k]

    def left_for(times, limit):
        t = sorted(times)
        return t[len(t) - limit] + WINDOW - now if len(t) >= limit else 0

    d, n = left_for(fails.get(dev, []), MAX_FAILS), left_for(net_fails.get(ip, []), NET_MAX)
    g = left_for([t for v in fails.values() for t in v], GLOBAL_MAX)
    left = max(d, n, g)
    reason = "" if left <= 0 else "device" if d == left else "network" if n == left else "everyone"
    return left > 0, int(left), reason


def locked(dev, ip):
    return lock_info(dev, ip)[0]


def lock_text(dev, ip):
    _, left, reason = lock_info(dev, ip)
    mins = max(1, (left + 59) // 60)
    if reason == "network":
        return (f"Too many failed attempts from devices on this network. Try again in about {mins} min. "
                f"Address {ip} \u00b7 Network code {dev_code('net:' + ip)}")
    if reason == "everyone":
        return (f"Too many failed attempts across all devices. Try again in about {mins} min. "
                f"Address {ip} \u00b7 Code {dev_code(dev)}")
    return (f"This device is locked after too many failed attempts. Try again in about {mins} min. "
            f"Address {ip} \u00b7 Device code {dev_code(dev)}")


def locked_error(dev, ip):
    return HTTPException(429, lock_text(dev, ip))


def load_bans():
    try:
        for r in json.loads(fernet.decrypt(get(BANS))):
            banned[r.get("dev") or r["ip"]] = {k: r.get(k, "") for k in ("when", "by", "ua", "ip")}
    except HTTPException as e:
        if e.status_code != 404:
            print("BANS load failed:", e.detail, flush=True)
    except Exception as e:
        print("BANS load failed:", type(e).__name__, flush=True)


def save_bans():
    try:
        put(BANS, fernet.encrypt(json.dumps([{"dev": d, **v} for d, v in banned.items()]).encode()))
        return True
    except HTTPException:
        return False


def blocked_page(ip, dev):
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Blocked</title>"
            "<body style='margin:0;min-height:100vh;display:grid;place-items:center;background:#150a35;color:#fff;"
            "font:16px/1.5 system-ui,sans-serif;text-align:center;padding:20px'><div style='max-width:420px'>"
            "<h1 style='margin:0 0 8px'>This device is blocked</h1>"
            f"<p>Address <b>{escape(ip)}</b></p><p style='font-size:1.8rem;letter-spacing:.2em;margin:8px 0'><b>{dev_code(dev)}</b></p>"
            "<p style='color:#cfc8ee'>If this is your device, tell the owner this code. They can unblock it from Telegram.</p></div>")


def find_key(code):
    for dev in set(banned) | set(fails):
        if dev_code(dev) == code:
            return "dev", dev
    for ip in net_fails:
        if dev_code("net:" + ip) == code:
            return "net", ip
    return None, None


def actor(uid):
    return next((n.title() for n, i in TG_USERS.items() if i == str(uid)), "Someone")


def tag_for(kind, key):
    if kind == "net":
        return f"Code: {dev_code('net:' + key)}\nAddress: {key}"
    return f"Code: {dev_code(key)}\nAddress: {(seen.get(key) or banned.get(key) or {}).get('ip', 'unknown')}"


def is_active(kind, key):
    if kind == "net":
        return len(net_fails.get(key, [])) >= NET_MAX
    return key in banned or len(fails.get(key, [])) >= MAX_FAILS


def entry(kind, key):
    if kind == "net":
        code, left = dev_code("net:" + key), lock_info("", key)[1]
        return (f"\U0001F310 Whole network timed out\nCode: {code}\nAddress: {key}\n"
                f"Failed tries from devices on it: {len(net_fails.get(key, []))}\n"
                f"Unlocks on its own in about {max(1, (left + 59) // 60)} min",
                {"inline_keyboard": [[{"text": "\u2705 Unblock network", "callback_data": "u:" + code}]]})
    info = seen.get(key) or banned.get(key) or {}
    code, dev, ip = dev_code(key), device_name(info.get("ua")), info.get("ip", "unknown")
    if key in banned:
        b = banned[key]
        return (f"\u26d4 Device banned forever\nCode: {code}\nAddress: {ip}\nDevice: {dev}\nBanned by {b['by']} on {b['when']}",
                {"inline_keyboard": [[{"text": "\u2705 Unban", "callback_data": "u:" + code}]]})
    left = lock_info(key, ip)[1]
    return (f"\U0001F512 Device timed out\nCode: {code}\nAddress: {ip}\nDevice: {dev}\nFailed tries: {len(fails.get(key, []))}\n"
            f"Unlocks on its own in about {max(1, (left + 59) // 60)} min",
            {"inline_keyboard": [[{"text": "\U0001F6AB Ban forever", "callback_data": "b:" + code},
                                  {"text": "\u2705 Unblock", "callback_data": "u:" + code}]]})


def send_timeouts(chat):
    lock_info("", "")  # tidy out old entries first
    devs = [d for d, ts in fails.items() if len(ts) >= MAX_FAILS and d not in banned]
    nets = [ip for ip, ts in net_fails.items() if len(ts) >= NET_MAX]
    everyone = sum(len(v) for v in fails.values()) >= GLOBAL_MAX
    if not (devs or nets or banned or everyone):
        tg_call("sendMessage", {"chat_id": chat, "text": "No devices are timed out or banned right now. \u2705"})
        return
    head = {"chat_id": chat, "text": f"Blocked: {len(devs)} devices timed out, {len(nets)} networks timed out, {len(banned)} banned."}
    if everyone:
        head["text"] += "\n\nEveryone is locked out right now, because of too many failed attempts from all devices combined."
        head["reply_markup"] = {"inline_keyboard": [[{"text": "Clear all lockouts", "callback_data": "c:all"}]]}
    tg_call("sendMessage", head)
    items = [("dev", d) for d in devs] + [("net", n) for n in nets] + [("dev", d) for d in banned]
    for kind, key in items[:12]:
        text, markup = entry(kind, key)
        tg_call("sendMessage", {"chat_id": chat, "text": text, "reply_markup": markup})
    if len(items) > 12:
        tg_call("sendMessage", {"chat_id": chat, "text": f"...and {len(items) - 12} more."})


def handle_message(m):
    uid, chat = str((m.get("from") or {}).get("id", "")), (m.get("chat") or {}).get("id")
    if uid not in TG_USERS.values() or not chat or (m.get("chat") or {}).get("type", "private") != "private":
        return  # strangers get no reply at all, and nothing is ever answered inside a group chat
    cmd = str(m.get("text", "")).split(" ")[0].split("@")[0].lower()
    if cmd in ("/timeouts", "/timeout", "/timeoutd", "/blocked"):
        send_timeouts(chat)
    elif cmd in ("/start", "/help"):
        tg_call("sendMessage", {"chat_id": chat, "text": "You are on the CheckVault list.\n\n/timeouts shows blocked devices, "
                                "and lets you unblock them or ban them forever."})


def admin_callback(cb):
    uid, msg = str((cb.get("from") or {}).get("id", "")), cb.get("message") or {}
    act, _, code = str(cb["data"]).partition(":")
    chat, mid = (msg.get("chat") or {}).get("id"), msg.get("message_id")

    def toast(t, alert=False):
        tg_call("answerCallbackQuery", {"callback_query_id": cb["id"], "text": t, "show_alert": alert})

    def say(text, kb=None):  # rewrite the message the button was on
        if chat and mid:
            tg_call("editMessageText", {"chat_id": chat, "message_id": mid, "text": text,
                                        "reply_markup": kb or {"inline_keyboard": []}})

    def tell_others(text):
        for c in TG_USERS.values():
            if c != uid:
                tg_call("sendMessage", {"chat_id": c, "text": text})

    if uid not in TG_USERS.values():
        return toast("Not allowed", True)
    who = actor(uid)
    if act == "c":
        fails.clear()
        net_fails.clear()
        toast("All lockouts cleared")
        say(f"All lockouts cleared by {who} at {stamp()}.")
        return tell_others(f"{who} cleared all CheckVault lockouts at {stamp()}.")
    kind, key = find_key(code)
    if not key:
        toast("That one is already clear.")
        return say("Already clear.")
    tag = tag_for(kind, key)
    if act == "x":
        toast("Cancelled")
        return say(*entry(kind, key)) if is_active(kind, key) else say("Already clear.")
    if act in ("b", "B") and kind == "net":
        return toast("A whole network can only be unblocked, not banned.", True)
    if act == "b":
        toast("Are you sure?")
        return say(f"Ban this device forever?\n{tag}\nIt is blocked from the whole site until someone unbans it. "
                   "Other devices on the same network are not affected.",
                   {"inline_keyboard": [[{"text": "Yes, ban forever", "callback_data": "B:" + code},
                                         {"text": "Cancel", "callback_data": "x:" + code}]]})
    if act == "B":
        info = seen.get(key) or {}
        banned[key] = {"when": stamp(), "by": who, "ua": info.get("ua", ""), "ip": info.get("ip", "unknown")}
        fails.pop(key, None)
        saved = save_bans()
        toast("Banned")
        say(f"\u26d4 Device banned forever by {who} at {stamp()}.\n{tag}" +
            ("" if saved else "\nNote: it could not be saved, so it is lost if the site restarts."))
        return tell_others(f"{who} banned a device forever.\n{tag}\nTime: {stamp()}")
    if act == "u":
        note = ""
        if kind == "net":
            net_fails.pop(key, None)
        else:
            if banned.pop(key, None) is not None:
                save_bans()
            fails.pop(key, None)
            _, _, why = lock_info(key, (seen.get(key) or {}).get("ip", ""))
            if why == "network":
                note = "\nIts whole network is still timed out. Use /timeouts and unblock the network too."
            elif why == "everyone":
                note = "\nEveryone is still locked by the combined limit. Use /timeouts, then Clear all lockouts."
        toast("Unblocked")
        say(f"\u2705 Unblocked by {who} at {stamp()}.\n{tag}{note}")
        return tell_others(f"{who} unblocked a device or network.\n{tag}\nTime: {stamp()}")


def auth(request: Request):
    path = request.url.path
    if path in ("/login", "/login/people", "/login/ask", "/login/status", "/login/lock", "/telegram/webhook", "/device.js"):
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
    ip, path = ip_of(request), request.url.path
    dev = read_device(request)
    fresh = not dev
    if fresh:
        dev = secrets.token_hex(16)
    request.state.device = dev
    if path.startswith("/login"):
        remember_device(dev, ip, request.headers.get("user-agent", ""))
    if dev in banned and path != "/telegram/webhook":
        return HTMLResponse(blocked_page(ip, dev), status_code=403)
    size = request.headers.get("content-length", "")
    if size.isdigit() and int(size) > 25 * 1024 * 1024:
        return JSONResponse({"detail": "Upload too large"}, status_code=413)
    r = await call_next(request)
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
    if fresh and path != "/telegram/webhook":
        r.set_cookie("cvd", dsigner.dumps(dev), max_age=DEVICE_COOKIE_SECONDS, httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return r


@app.get("/device.js")
def device_js():
    return FileResponse(Path(__file__).parent / "device.js", media_type="text/javascript")


@app.get("/login")
def login_page():
    return FileResponse(Path(__file__).parent / "login.html")


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""), code: str = Form("")):
    ip, dev = ip_of(request), dev_of(request)
    if locked(dev, ip):
        raise locked_error(dev, ip)
    code = code.replace(" ", "")
    user_ok = valid_user(username)
    pass_ok = secrets.compare_digest(password.encode(), PASSWORD.encode())
    code_ok = bool(TOTP) and TOTP.verify(code, valid_window=1) and code != last_code[0]
    if not (user_ok and pass_ok and code_ok):
        note_fail(dev, ip)
        raise HTTPException(401, "Wrong username, password, or code")
    fails.pop(dev, None)
    last_code[0] = code
    return start_session()


def start_session(extra=None):
    resp = JSONResponse({"ok": True, **(extra or {})})
    resp.set_cookie("session", signer.dumps("ok"), max_age=SESSION_SECONDS,
                    httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return resp


@app.get("/login/lock")
def lock_status(request: Request):
    ip, dev = ip_of(request), dev_of(request)
    if not locked(dev, ip):
        return {"locked": False}
    return {"locked": True, "message": lock_text(dev, ip)}


@app.get("/login/people")
def people():
    return {"people": list(TG_USERS) if TG_TOKEN else []}


@app.post("/login/ask")
def ask(request: Request, username: str = Form(""), password: str = Form(""), who: str = Form("")):
    ip, dev = ip_of(request), dev_of(request)
    if locked(dev, ip):
        raise locked_error(dev, ip)
    if not TG_TOKEN:
        raise HTTPException(400, "Telegram sign-in is not set up.")
    who, now = who.strip().lower(), time.time()
    for k in [k for k, v in reqs.items() if v["exp"] < now - 60]:
        del reqs[k]
    rid, poll = secrets.token_hex(16), secrets.token_urlsafe(24)
    r = {"poll": poll, "chat": None, "msg": None, "who": who, "ip": ip, "dev": dev, "status": "pending", "exp": now + ASK_SECONDS}
    reqs[rid] = r
    if not (valid_user(username) and secrets.compare_digest(password.encode(), PASSWORD.encode()) and who in TG_USERS):
        note_fail(dev, ip)  # wrong details look exactly like right ones to the visitor
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
    if update.get("message"):
        handle_message(update["message"])
        return {"ok": True}
    cb = update.get("callback_query")
    if not cb:
        return {"ok": True}
    if str(cb.get("data", ""))[:2] in ("b:", "B:", "x:", "u:", "c:"):
        admin_callback(cb)
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
        note_fail(r["dev"], r["ip"], MAX_FAILS, network=False)  # that one device is timed out for 15 minutes
        tg_call("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Denied and logged"})
        tg_close(r, f"Denied at {stamp()}. The attempt from {r['ip']} was logged and that device is blocked for 15 minutes.")
        for chat in TG_USERS.values():
            if chat != r["chat"]:
                tg_call("sendMessage", {"chat_id": chat, "text": f"Warning: {r['who'].title()} tapped It's not me on a "
                        f"CheckVault sign-in.\nTime: {stamp()}\nFrom: {r['ip']}\nThat device is blocked for 15 minutes."})
    return {"ok": True}


def _storage_check():
    import platform
    print("Python version:", platform.python_version(), flush=True)
    if not BUCKET:
        print("STORAGE CHECK: no bucket set, using local folder", flush=True)
        return
    try:
        s3.put_object(Bucket=BUCKET, Key="healthcheck.txt", Body=b"ok")
        print("STORAGE CHECK: upload to Backblaze works", flush=True)
    except Exception as e:  # the message holds the endpoint and bucket name, never the keys
        print("STORAGE CHECK FAILED:", type(e).__name__, str(e)[:400], flush=True)


@app.on_event("startup")
def storage_check():
    threading.Thread(target=_storage_check, daemon=True).start()


def _set_webhook():
    tg_call("setWebhook", {"url": f"{PUBLIC_URL}/telegram/webhook", "secret_token": TG_SECRET,
                           "allowed_updates": ["callback_query", "message"], "drop_pending_updates": True})
    tg_call("setMyCommands", {"commands": [{"command": "timeouts", "description": "Show blocked devices"}]})


@app.on_event("startup")
def bans_startup():
    threading.Thread(target=load_bans, daemon=True).start()


@app.on_event("startup")
def register_webhook():
    if TG_TOKEN and PUBLIC_URL:
        threading.Thread(target=_set_webhook, daemon=True).start()


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
def add_check(
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
        blob = f.file.read()
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
