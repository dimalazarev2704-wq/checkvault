import base64, hashlib, hmac, io, ipaddress, json, math, os, re, secrets, threading, time, urllib.parse, urllib.request, uuid
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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
LOCKS = "locks.enc"
MAX_ADD = 30 * 86400  # the most time that can be added at once
extra = {}         # device id (or "net:<address>") -> when an added lockout ends (epoch seconds)
pending_time = {}  # Telegram user id -> the timeout they are about to add time to
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


def fmt_dur(s):
    m = max(1, (max(0, int(s)) + 59) // 60)
    if m < 60:
        return f"{m} min"
    h, mm = divmod(m, 60)
    if h < 24:
        return f"{h} h" + (f" {mm} min" if mm else "")
    d, hh = divmod(h, 24)
    return f"{d} d" + (f" {hh} h" if hh else "")


def read_device(request):
    """The id this browser was given on its first visit, or "" if it has none (or a forged one)."""
    try:
        d = dsigner.loads(request.cookies.get("cvd", ""))
    except BadSignature:
        return ""
    return d if isinstance(d, str) and re.fullmatch(r"[0-9a-f]{32}", d) else ""


def dev_of(request):
    st = getattr(request, "state", None)
    return getattr(st, "device", "") or read_device(request) or "x:" + ip_of(request)


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
    for k in [k for k, v in extra.items() if v <= now]:
        del extra[k]

    def left_for(times, limit):
        t = sorted(times)
        return t[len(t) - limit] + WINDOW - now if len(t) >= limit else 0

    d, n = left_for(fails.get(dev, []), MAX_FAILS), left_for(net_fails.get(ip, []), NET_MAX)
    g = left_for([t for v in fails.values() for t in v], GLOBAL_MAX)
    options = [("device", d), ("device", extra.get(dev, 0) - now), ("network", n), ("network", extra.get("net:" + ip, 0) - now),
               ("everyone", g)]
    left = max(v for _, v in options)
    reason = next((r for r, v in options if v == left), "") if left > 0 else ""
    return left > 0, math.ceil(left) if left > 0 else 0, reason


def locked(dev, ip):
    return lock_info(dev, ip)[0]


def lock_text(dev, ip):
    _, left, reason = lock_info(dev, ip)
    wait = fmt_dur(left)
    if reason == "network":
        return (f"Too many failed attempts from devices on this network. Try again in about {wait}. "
                f"Address {ip} \u00b7 Network code {dev_code('net:' + ip)}")
    if reason == "everyone":
        return (f"Too many failed attempts across all devices. Try again in about {wait}. "
                f"Address {ip} \u00b7 Code {dev_code(dev)}")
    return (f"This device is locked after too many failed attempts. Try again in about {wait}. "
            f"Address {ip} \u00b7 Device code {dev_code(dev)}")


def lock_details(dev, ip):
    is_locked, left, reason = lock_info(dev, ip)
    if not is_locked:
        return {"locked": False}
    net = reason == "network"
    return {"locked": True, "seconds": left, "reason": reason, "ip": ip, "label": "Network code" if net else "Device code",
            "code": dev_code("net:" + ip if net else dev), "message": lock_text(dev, ip)}


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


_loading = {"on": False}  # true while the saved bans, added time and passkeys are being read at start-up


def wait_loaded():
    """Saving before the lists are read would overwrite them with a shorter list, so wait (a few seconds at most)."""
    t = time.time()
    while _loading["on"] and time.time() - t < 8:
        time.sleep(0.05)


def save_bans():
    wait_loaded()
    try:
        put(BANS, fernet.encrypt(json.dumps([{"dev": d, **v} for d, v in banned.items()]).encode()))
        return True
    except HTTPException:
        return False


def save_locks():
    wait_loaded()
    now = time.time()
    try:
        until = {k: v for k, v in extra.items() if v > now}
        put(LOCKS, fernet.encrypt(json.dumps({"until": until, "seen": {k: seen[k] for k in until if k in seen}}).encode()))
        return True
    except HTTPException:
        return False


def load_locks():
    try:
        now = time.time()
        data = json.loads(fernet.decrypt(get(LOCKS)))
        for k, v in data.get("until", data).items():
            if isinstance(v, (int, float)) and v > now:
                extra[k] = v
        for k, v in (data.get("seen") or {}).items():
            if k in extra and k not in seen:
                seen[k] = {"ua": str(v.get("ua", ""))[:300], "ip": str(v.get("ip", "unknown")), "last": 0}
    except HTTPException as e:
        if e.status_code != 404:
            print("LOCKS load failed:", e.detail, flush=True)
    except Exception as e:
        print("LOCKS load failed:", type(e).__name__, flush=True)


def blocked_page(ip, dev):
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Blocked</title>"
            "<body style='margin:0;min-height:100vh;display:grid;place-items:center;background:#000;color:#fff;"
            "font:16px/1.5 system-ui,sans-serif;text-align:center;padding:20px'><div style='max-width:420px'>"
            "<h1 style='margin:0 0 8px'>This device is blocked</h1>"
            f"<p>Address <b>{escape(ip)}</b></p><p style='font-size:1.8rem;letter-spacing:.2em;margin:8px 0'><b>{dev_code(dev)}</b></p>"
            "<p style='color:#cfc8ee'>If this is your device, tell the owner this code. They can unblock it from Telegram.</p></div>")


def find_key(code):
    for dev in set(banned) | set(fails) | {k for k in extra if not k.startswith("net:")}:
        if dev_code(dev) == code:
            return "dev", dev
    for ip in set(net_fails) | {k[4:] for k in extra if k.startswith("net:")}:
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
    now = time.time()
    if kind == "net":
        return len(net_fails.get(key, [])) >= NET_MAX or extra.get("net:" + key, 0) > now
    return key in banned or len(fails.get(key, [])) >= MAX_FAILS or extra.get(key, 0) > now


def entry(kind, key):
    if kind == "net":
        code, left = dev_code("net:" + key), lock_info("", key)[1]
        return (f"\U0001F310 Whole network timed out\nCode: {code}\nAddress: {key}\n"
                f"Failed tries from devices on it: {len(net_fails.get(key, []))}\n"
                f"Unlocks in about {fmt_dur(left)}",
                {"inline_keyboard": [[{"text": "\u2705 Unblock network", "callback_data": "u:" + code},
                                      {"text": "\u23f1 Add time", "callback_data": "t:" + code}]]})
    info = seen.get(key) or banned.get(key) or {}
    code, dev, ip = dev_code(key), device_name(info.get("ua")), info.get("ip", "unknown")
    if key in banned:
        b = banned[key]
        return (f"\u26d4 Device banned forever\nCode: {code}\nAddress: {ip}\nDevice: {dev}\nBanned by {b['by']} on {b['when']}",
                {"inline_keyboard": [[{"text": "\u2705 Unban", "callback_data": "u:" + code}]]})
    left = lock_info(key, ip)[1]
    return (f"\U0001F512 Device timed out\nCode: {code}\nAddress: {ip}\nDevice: {dev}\nFailed tries: {len(fails.get(key, []))}\n"
            f"Unlocks in about {fmt_dur(left)}",
            {"inline_keyboard": [[{"text": "\U0001F6AB Ban forever", "callback_data": "b:" + code},
                                  {"text": "\u2705 Unblock", "callback_data": "u:" + code}],
                                 [{"text": "\u23f1 Add time", "callback_data": "t:" + code}]]})


def send_timeouts(chat):
    lock_info("", "")  # tidy out old entries first
    now = time.time()
    devs = sorted(d for d in ({d for d, ts in fails.items() if len(ts) >= MAX_FAILS} |
                              {k for k, v in extra.items() if v > now and not k.startswith("net:")}) if d not in banned)
    nets = sorted({ip for ip, ts in net_fails.items() if len(ts) >= NET_MAX} |
                  {k[4:] for k, v in extra.items() if v > now and k.startswith("net:")})
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


def parse_duration(text):
    """'30', '30m', '2h', '1d', '1h30m', '1.5 hours', '90s' -> seconds (a bare number means minutes); None if unclear."""
    t = text.strip().lower()[:40]
    if re.sub(r"\d+(?:\.\d+)?\s*[a-z]*", "", t).strip():
        return None  # something left over that is not a number with a unit
    units = {"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "": 60, "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
             "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600, "d": 86400, "day": 86400, "days": 86400}
    total = 0.0
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)\s*([a-z]*)", t):
        if unit not in units:
            return None
        total += float(num) * units[unit]
    return int(total) if total > 0 else None


def add_time(kind, key, secs):
    """Push a timeout's end further away by secs. Returns the seconds left afterwards."""
    now = time.time()
    ip = key if kind == "net" else (seen.get(key) or {}).get("ip", "")
    left = lock_info("" if kind == "net" else key, ip)[1]
    extra["net:" + key if kind == "net" else key] = now + left + secs
    save_locks()
    return left + secs


def notify_others(uid, text):
    for c in TG_USERS.values():
        if c != str(uid):
            tg_call("sendMessage", {"chat_id": c, "text": text})


def answer_time(uid, chat, p, text):
    def say(t):
        tg_call("sendMessage", {"chat_id": chat, "text": t})

    if text.lower() in ("cancel", "stop", "no"):
        pending_time.pop(uid, None)
        return say("Cancelled. Nothing was changed.")
    secs = parse_duration(text)
    if secs is None:
        return say("I did not understand that. Type it like 30m, 2h or 1d (a plain number means minutes), or type cancel.")
    if secs < 60:
        return say("The least I can add is 1 minute. Type a longer time, or cancel.")
    if secs > MAX_ADD:
        return say("That is more than 30 days. Type a shorter time, or use Ban forever for a permanent block.")
    pending_time.pop(uid, None)
    kind, key = p["kind"], p["key"]
    if not is_active(kind, key):
        return say("That one is already clear, so there was nothing to extend.")
    left = add_time(kind, key, secs)
    tag = tag_for(kind, key)
    say(f"\u23f1 Added {fmt_dur(secs)}.\n{tag}\nIt now unlocks in about {fmt_dur(left)}.")
    notify_others(uid, f"{actor(uid)} added {fmt_dur(secs)} to a timeout.\n{tag}\nIt now unlocks in about {fmt_dur(left)}.")


def handle_message(m):
    uid, chat = str((m.get("from") or {}).get("id", "")), (m.get("chat") or {}).get("id")
    if uid not in TG_USERS.values() or not chat or (m.get("chat") or {}).get("type", "private") != "private":
        return  # strangers get no reply at all, and nothing is ever answered inside a group chat
    text = str(m.get("text", "")).strip()
    p = pending_time.get(uid)
    if p and time.time() > p["exp"]:
        pending_time.pop(uid, None)
        p = None
    if p and text and not text.startswith("/"):
        return answer_time(uid, chat, p, text)
    cmd = text.split(" ")[0].split("@")[0].lower()
    if cmd.startswith("/"):
        pending_time.pop(uid, None)  # any command cancels a half-finished "add time"
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
        notify_others(uid, text)

    if uid not in TG_USERS.values():
        return toast("Not allowed", True)
    who = actor(uid)
    if act == "c":
        fails.clear()
        net_fails.clear()
        extra.clear()
        save_locks()
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
    if act == "t":
        if not is_active(kind, key) or key in banned:
            toast("Nothing to extend.", True)
            return say("That one is not timed out any more.")
        pending_time[uid] = {"kind": kind, "key": key, "exp": time.time() + 300}
        toast("Type how much time to add")
        return tg_call("sendMessage", {"chat_id": chat or uid, "text": f"How much time should I add?\n{tag}\n\nType it like 30m, 2h or 1d "
                                       "(a plain number means minutes). Type cancel to stop.",
                                       "reply_markup": {"force_reply": True, "input_field_placeholder": "e.g. 30m, 2h, 1d"}})
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
        if extra.pop(key, None) is not None:
            save_locks()
        saved = save_bans()
        toast("Banned")
        say(f"\u26d4 Device banned forever by {who} at {stamp()}.\n{tag}" +
            ("" if saved else "\nNote: it could not be saved, so it is lost if the site restarts."))
        return tell_others(f"{who} banned a device forever.\n{tag}\nTime: {stamp()}")
    if act == "u":
        note = ""
        if kind == "net":
            net_fails.pop(key, None)
            extra.pop("net:" + key, None)
        else:
            if banned.pop(key, None) is not None:
                save_bans()
            fails.pop(key, None)
            extra.pop(key, None)
        save_locks()
        if kind == "dev":
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
    if path in ("/login", "/login/people", "/login/ask", "/login/status", "/login/lock", "/login/passkey", "/login/passkey/options",
                "/login/passkey/available", "/telegram/webhook", "/device.js"):
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
    if path.startswith(("/login", "/api")) and "Cache-Control" not in r.headers:
        r.headers["Cache-Control"] = "no-store"
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
    return lock_details(dev_of(request), ip_of(request))


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
    if str(cb.get("data", ""))[:2] in ("b:", "B:", "x:", "u:", "c:", "t:"):
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


def _load_saved_state():
    try:
        load_bans()
        load_locks()
        load_passkeys()
    finally:
        _loading["on"] = False


@app.on_event("startup")
def bans_startup():
    _loading["on"] = True
    threading.Thread(target=_load_saved_state, daemon=True).start()


@app.on_event("startup")
def register_webhook():
    if TG_TOKEN and PUBLIC_URL:
        threading.Thread(target=_set_webhook, daemon=True).start()


# ---- passkeys (WebAuthn): sign in with Face ID, a fingerprint or a device PIN, next to the password + code ----
PASSKEYS_FILE = "passkeys.enc"
RP_ORIGIN = PUBLIC_URL  # e.g. https://checkvault.onrender.com; a passkey only works on exactly this address
RP_ID = urllib.parse.urlparse(PUBLIC_URL).hostname or ""
passkeys = {}    # credential id (base64url) -> {"alg", "pub" (base64 DER), "count", "name", "added", "used"}
challenges = {}  # challenge id -> {"c", "kind", "dev", "name", "exp"}: each is good for one try, for 3 minutes


def passkeys_ready():
    return bool(RP_ID and PUBLIC_URL.startswith("https://"))


print("Passkeys:", f"ready for {RP_ID}" if passkeys_ready() else "off (the site's https address is not known)", flush=True)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    if not isinstance(s, str) or not s or len(s) > 20000 or not re.fullmatch(r"[A-Za-z0-9_-]+", s):
        raise ValueError("bad base64")
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4), validate=True)


def cbor(data, i=0, depth=0):
    """Read one CBOR item (the small part of CBOR that WebAuthn uses). Returns (value, next position)."""
    if depth > 8 or i >= len(data):
        raise ValueError("bad cbor")
    major, info = data[i] >> 5, data[i] & 31
    i += 1
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if i + size > len(data):
            raise ValueError("bad cbor")
        n = int.from_bytes(data[i:i + size], "big")
        i += size
    else:
        raise ValueError("unsupported cbor")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(data):
            raise ValueError("bad cbor")
        raw = data[i:i + n]
        return (raw if major == 2 else raw.decode("utf-8")), i + n
    if major in (4, 5) and n <= 64:
        out = [] if major == 4 else {}
        for _ in range(n):
            k, i = cbor(data, i, depth + 1)
            if major == 4:
                out.append(k)
            else:
                v, i = cbor(data, i, depth + 1)
                if isinstance(k, (list, dict)):
                    raise ValueError("bad cbor key")
                out[k] = v
        return out, i
    raise ValueError("unsupported cbor")


def parse_auth_data(ad, with_credential):
    if len(ad) < 37:
        raise ValueError("short authenticator data")
    out = {"rp": ad[:32], "flags": ad[32], "count": int.from_bytes(ad[33:37], "big")}
    if with_credential:
        if not out["flags"] & 0x40 or len(ad) < 55:
            raise ValueError("no credential in the answer")
        n = int.from_bytes(ad[53:55], "big")
        if n == 0 or n > 1023 or len(ad) < 55 + n:
            raise ValueError("bad credential id")
        out["cred_id"] = ad[55:55 + n]
        out["key"], _ = cbor(ad, 55 + n)
    return out


def cose_to_public(key):
    """The public key, as bytes, for the two kinds phones and computers use: ES256 (P-256) and RS256."""
    if not isinstance(key, dict):
        raise ValueError("bad key")
    alg = key.get(3)
    if key.get(1) == 2 and alg == -7 and key.get(-1) == 1 and isinstance(key.get(-2), bytes) and isinstance(key.get(-3), bytes) \
            and len(key[-2]) == 32 and len(key[-3]) == 32:
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1()).public_key()
    elif key.get(1) == 3 and alg == -257 and isinstance(key.get(-1), bytes) and isinstance(key.get(-2), bytes):
        pub = rsa.RSAPublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-1], "big")).public_key()
        if pub.key_size < 2048:
            raise ValueError("key too small")
    else:
        raise ValueError("unsupported key type")
    return alg, pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def check_client_data(raw, kind, challenge):
    cd = json.loads(raw.decode("utf-8"))
    if cd.get("type") != kind or cd.get("origin") != RP_ORIGIN or cd.get("crossOrigin") not in (None, False):
        raise ValueError("wrong site or kind")
    if not hmac.compare_digest(str(cd.get("challenge")).encode(), challenge.encode()):
        raise ValueError("wrong challenge")


opt_hits = {}  # address -> times it asked for a sign-in challenge in the last minute


def calm_enough(ip, limit=20, per=60):
    now = time.time()
    hits = [t for t in opt_hits.get(ip, []) if now - t < per]
    if len(hits) >= limit:
        opt_hits[ip] = hits
        return False
    opt_hits[ip] = hits + [now]
    if len(opt_hits) > 1000:
        for k in [k for k, v in opt_hits.items() if not v or now - v[-1] >= per]:
            del opt_hits[k]
    return True


def new_challenge(kind, dev, name=""):
    now = time.time()
    for k in [k for k, v in challenges.items() if v["exp"] < now]:
        del challenges[k]
    mine = sorted((k for k, v in challenges.items() if v["dev"] == dev and v["kind"] == kind), key=lambda k: challenges[k]["exp"])
    for k in mine[:max(0, len(mine) - 4)]:  # at most 5 open per device, counting the one made below
        del challenges[k]
    if len(challenges) > 300:  # a flood pushes out the OLDEST requests; it can never refuse a real person
        for k in sorted(challenges, key=lambda k: challenges[k]["exp"])[:100]:
            del challenges[k]
    cid, ch = secrets.token_urlsafe(16), b64u(secrets.token_bytes(32))
    challenges[cid] = {"c": ch, "kind": kind, "dev": dev, "name": name[:40], "exp": now + 180}
    return cid, ch


def take_challenge(cid, kind, dev):
    v = challenges.pop(str(cid), None)  # used up even if the answer turns out wrong
    if not v or v["kind"] != kind or v["dev"] != dev or v["exp"] < time.time():
        raise ValueError("that request expired")
    return v


def save_passkeys():
    wait_loaded()
    try:
        put(PASSKEYS_FILE, fernet.encrypt(json.dumps(passkeys).encode()))
        return True
    except HTTPException:
        return False


def load_passkeys():
    try:
        for k, v in json.loads(fernet.decrypt(get(PASSKEYS_FILE))).items():
            if isinstance(v, dict) and v.get("pub") and v.get("alg") in (-7, -257):
                passkeys[k] = {"alg": v["alg"], "pub": v["pub"], "count": int(v.get("count", 0)), "name": str(v.get("name", "Passkey"))[:40],
                               "added": str(v.get("added", "")), "used": str(v.get("used", ""))}
    except HTTPException as e:
        if e.status_code != 404:
            print("PASSKEYS load failed:", e.detail, flush=True)
    except Exception as e:
        print("PASSKEYS load failed:", type(e).__name__, flush=True)


def register_passkey(cid, cred_id, client_json, attestation, dev):
    chal = take_challenge(cid, "create", dev)
    check_client_data(client_json, "webauthn.create", chal["c"])
    att, _ = cbor(attestation)
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise ValueError("bad attestation")
    ad = parse_auth_data(att["authData"], True)
    if not hmac.compare_digest(ad["rp"], hashlib.sha256(RP_ID.encode()).digest()):
        raise ValueError("made for another site")
    if ad["flags"] & 0x05 != 0x05:
        raise ValueError("the device did not check your face, fingerprint or PIN")
    pid = b64u(ad["cred_id"])
    if pid != cred_id:
        raise ValueError("credential id mismatch")
    if pid in passkeys:
        raise ValueError("already added")
    alg, der = cose_to_public(ad["key"])
    passkeys[pid] = {"alg": alg, "pub": base64.b64encode(der).decode(), "count": ad["count"], "name": chal["name"] or "Passkey",
                     "added": stamp(), "used": ""}
    if not save_passkeys():
        del passkeys[pid]
        raise ValueError("could not save")
    return pid


def verify_passkey(cid, cred_id, client_json, auth_data, signature, dev):
    chal = take_challenge(cid, "get", dev)
    rec = passkeys.get(cred_id)
    if rec is None:
        raise ValueError("unknown passkey")
    check_client_data(client_json, "webauthn.get", chal["c"])
    ad = parse_auth_data(auth_data, False)
    if not hmac.compare_digest(ad["rp"], hashlib.sha256(RP_ID.encode()).digest()):
        raise ValueError("made for another site")
    if ad["flags"] & 0x05 != 0x05:
        raise ValueError("the device did not check your face, fingerprint or PIN")
    pub = serialization.load_der_public_key(base64.b64decode(rec["pub"]))
    signed = auth_data + hashlib.sha256(client_json).digest()
    try:
        if rec["alg"] == -7:
            pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise ValueError("bad signature")
    if rec["count"] and ad["count"] <= rec["count"]:
        raise ValueError("the sign-in counter went backwards: this passkey may be a copy")
    rec["count"], rec["used"] = max(rec["count"], ad["count"]), stamp()
    save_passkeys()
    return rec


def notify_all(text):
    if TG_TOKEN and TG_USERS:
        threading.Thread(target=lambda: [tg_call("sendMessage", {"chat_id": c, "text": text}) for c in TG_USERS.values()], daemon=True).start()


@app.get("/login/passkey/available")
def passkey_available():
    return {"available": passkeys_ready() and bool(passkeys)}


@app.post("/login/passkey/options")
def passkey_login_options(request: Request):
    ip, dev = ip_of(request), dev_of(request)
    if locked(dev, ip):
        raise locked_error(dev, ip)
    if not passkeys_ready() or not passkeys:
        raise HTTPException(400, "No passkeys are set up yet.")
    if not calm_enough(ip):
        raise HTTPException(429, "Too many tries. Wait a minute.")
    cid, ch = new_challenge("get", dev)
    return {"cid": cid, "challenge": ch, "rpId": RP_ID, "timeout": 120000, "userVerification": "required"}


@app.post("/login/passkey")
def passkey_login(request: Request, data: dict = Body(...)):
    ip, dev = ip_of(request), dev_of(request)
    if locked(dev, ip):
        raise locked_error(dev, ip)
    try:
        r = data.get("response") or {}
        rec = verify_passkey(data.get("cid"), data.get("id"), unb64u(r.get("clientDataJSON")), unb64u(r.get("authenticatorData")),
                             unb64u(r.get("signature")), dev)
    except Exception:
        note_fail(dev, ip)
        raise HTTPException(401, "That passkey didn't work")
    fails.pop(dev, None)
    notify_all(f"Passkey sign-in: {rec['name']}\nTime: {stamp()}\nFrom: {ip}\nCode: {dev_code(dev)}")
    return start_session()


def passkey_list():
    return {"enabled": passkeys_ready(), "items": [{"id": k, "name": v["name"], "added": v["added"], "used": v["used"]} for k, v in passkeys.items()]}


@app.get("/api/passkeys")
def passkeys_get():
    return passkey_list()


@app.post("/api/passkeys/options")
def passkey_register_options(request: Request, data: dict = Body(None)):
    if not passkeys_ready():
        raise HTTPException(400, "Passkeys need the site's secure address to be set up first.")
    label = str((data or {}).get("name", "")).strip()[:40] or "CheckVault passkey"
    cid, ch = new_challenge("create", dev_of(request), label)
    # a different user id each time, so adding a second passkey never overwrites the first one on the same device
    return {"cid": cid, "challenge": ch, "rp": {"name": "CheckVault", "id": RP_ID},
            "user": {"id": b64u(secrets.token_bytes(16)), "name": label, "displayName": label},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}], "timeout": 120000,
            "attestation": "none",
            "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
            "excludeCredentials": [{"type": "public-key", "id": k} for k in passkeys]}


@app.post("/api/passkeys")
def passkey_register(request: Request, data: dict = Body(...)):
    try:
        r = data.get("response") or {}
        pid = register_passkey(data.get("cid"), data.get("id"), unb64u(r.get("clientDataJSON")), unb64u(r.get("attestationObject")),
                               dev_of(request))
    except Exception as e:
        print("PASSKEY add failed:", type(e).__name__, str(e)[:100], flush=True)
        raise HTTPException(400, "That passkey could not be saved. Try again.")
    notify_all(f"A passkey was added: {passkeys[pid]['name']}\nTime: {stamp()}")
    return passkey_list()


@app.delete("/api/passkeys/{pid}")
def passkey_remove(pid: str):
    rec = passkeys.pop(pid, None)
    if rec is None:
        raise HTTPException(404, "Not found")
    if not save_passkeys():
        passkeys[pid] = rec
        raise HTTPException(502, "Could not save the change. Try again.")
    notify_all(f"A passkey was removed: {rec['name']}\nTime: {stamp()}")
    return passkey_list()


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
        img.draft("RGB", (2400, 2400))  # JPEGs decode at reduced size, saving memory
        return ImageOps.exif_transpose(img).convert("RGB")
    except Exception:
        raise HTTPException(400, "That file is not a valid image")


def jpeg(img, size, quality):
    img = img.copy()
    img.thumbnail((size, size))
    out = io.BytesIO()
    img.save(out, "JPEG", quality=quality, optimize=True)  # re-encoding also strips GPS/EXIF data
    return out.getvalue()


# ---- store logos: the small icon each store's own website uses, fetched once and remembered ----
# Built in, so the logos work even if stores.json is missing. stores.json (next to this file) only ADDS stores.
DEFAULT_STORES = json.loads("""{"walmart":"walmart.com","wal mart":"walmart.com","sams club":"samsclub.com","target":"target.com","costco":"costco.com","kroger":"kroger.com","publix":"publix.com","food lion":"foodlion.com","harris teeter":"harristeeter.com","lowes foods":"lowesfoods.com","aldi":"aldi.us","lidl":"lidl.com","whole foods":"wholefoodsmarket.com","trader joes":"traderjoes.com","safeway":"safeway.com","wegmans":"wegmans.com","heb":"heb.com","h e b":"heb.com","meijer":"meijer.com","giant eagle":"gianteagle.com","dollar general":"dollargeneral.com","dollar tree":"dollartree.com","family dollar":"familydollar.com","five below":"fivebelow.com","amazon":"amazon.com","home depot":"homedepot.com","lowes":"lowes.com","menards":"menards.com","ace hardware":"acehardware.com","harbor freight":"harborfreight.com","tractor supply":"tractorsupply.com","ikea":"ikea.com","best buy":"bestbuy.com","apple":"apple.com","micro center":"microcenter.com","gamestop":"gamestop.com","staples":"staples.com","office depot":"officedepot.com","bed bath and beyond":"bedbathandbeyond.com","homegoods":"homegoods.com","tj maxx":"tjmaxx.tjx.com","t j maxx":"tjmaxx.tjx.com","marshalls":"marshalls.com","ross":"rossstores.com","burlington":"burlington.com","old navy":"oldnavy.gap.com","gap":"gap.com","kohls":"kohls.com","macys":"macys.com","jcpenney":"jcpenney.com","nordstrom":"nordstrom.com","ulta":"ulta.com","sephora":"sephora.com","bath and body works":"bathandbodyworks.com","petsmart":"petsmart.com","petco":"petco.com","michaels":"michaels.com","joann":"joann.com","hobby lobby":"hobbylobby.com","barnes and noble":"barnesandnoble.com","dicks sporting goods":"dickssportinggoods.com","academy sports":"academy.com","autozone":"autozone.com","oreilly auto parts":"oreillyauto.com","oreilly":"oreillyauto.com","advance auto parts":"advanceautoparts.com","cvs":"cvs.com","walgreens":"walgreens.com","rite aid":"riteaid.com","starbucks":"starbucks.com","mcdonalds":"mcdonalds.com","chick fil a":"chick-fil-a.com","burger king":"bk.com","wendys":"wendys.com","taco bell":"tacobell.com","subway":"subway.com","chipotle":"chipotle.com","dunkin":"dunkindonuts.com","dunkin donuts":"dunkindonuts.com","panera":"panerabread.com","dominos":"dominos.com","pizza hut":"pizzahut.com","papa johns":"papajohns.com","kfc":"kfc.com","popeyes":"popeyes.com","five guys":"fiveguys.com","waffle house":"wafflehouse.com","cook out":"cookout.com","cookout":"cookout.com","bojangles":"bojangles.com","zaxbys":"zaxbys.com","sonic":"sonicdrivein.com","panda express":"pandaexpress.com","jersey mikes":"jerseymikes.com","jimmy johns":"jimmyjohns.com","shell":"shell.us","exxon":"exxon.com","bp":"bp.com","wawa":"wawa.com","sheetz":"sheetz.com","quiktrip":"quiktrip.com","7 eleven":"7-eleven.com","circle k":"circlek.com","speedway":"speedway.com","chevron":"chevron.com","murphy usa":"murphyusa.com","racetrac":"racetrac.com","uber":"uber.com","lyft":"lyft.com","usps":"usps.com","fedex":"fedex.com","ups store":"theupsstore.com"}""")
STORES = {}  # normal-form store name -> website


def norm_store(name):
    return re.sub(r"[^a-z0-9]+", " ", str(name).lower().replace("'", "").replace("&", " and ")).split()


def add_stores(items):
    for k, v in items.items():
        if isinstance(v, str) and re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", v.lower()) and norm_store(k):
            STORES[" ".join(norm_store(k))] = v.lower()


add_stores(DEFAULT_STORES)
try:
    add_stores(json.loads((Path(__file__).parent / "stores.json").read_text("utf-8")))
except Exception as _e:
    print("stores.json not loaded (the built-in list still works):", type(_e).__name__, flush=True)
print("Store logos:", len(STORES), "stores known", flush=True)
logos = {}  # website -> (png bytes or None, remembered until)
logo_lock = threading.Lock()


def store_domain(name):
    """Which website belongs to a typed store name. Only sites in the list are ever contacted."""
    t = norm_store(name)
    for cut in range(len(t), 0, -1):  # "Walmart Supercenter #123" -> "walmart"
        d = STORES.get(" ".join(t[:cut]))
        if d:
            return d
    return None


def fetch_logo(domain, trace=None, fresh=False):
    """Ask the icon services for a store's icon, keep the best one. Google's tiny answers can be a generic globe,
    so from Google only 32 px and up counts; DuckDuckGo and the store's own site give a real icon, so 16 px and up counts."""
    with logo_lock:  # one fetch at a time; everyone else then finds it already remembered
        now = time.time()
        hit = logos.get(domain)
        if hit and hit[1] > now and not fresh:
            return hit[0]
        best = None
        for name, url, smallest in (("google", f"https://www.google.com/s2/favicons?domain={domain}&sz=128", 32),
                                    ("duckduckgo", f"https://icons.duckduckgo.com/ip3/{domain}.ico", 16),
                                    ("the store's own site", f"https://{domain}/favicon.ico", 16)):
            if best is not None and name == "the store's own site":
                continue  # only a last resort
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 CheckVault"})
                raw = urllib.request.urlopen(req, timeout=4).read(300_000)
                img = Image.open(io.BytesIO(raw))
                img.load()
                size = min(img.size)
                if trace is not None:
                    trace.append({"source": name, "answered": True, "size": list(img.size), "accepted": size >= smallest})
                if size < smallest:
                    continue
                if best is None or size > best[0]:
                    img = img.convert("RGBA")
                    img.thumbnail((64, 64))
                    out = io.BytesIO()
                    img.save(out, "PNG")
                    best = (size, out.getvalue())
                if size >= 48:
                    break  # good enough, no need to ask the next one
            except Exception as e:
                if trace is not None:
                    trace.append({"source": name, "answered": False, "error": f"{type(e).__name__}: {str(e)[:120]}"})
        png = best[1] if best else None
        if png is None:
            print("LOGO: no usable icon for", domain, flush=True)
        logos[domain] = (png, now + (86400 if png else 300))  # a miss is only remembered for 5 minutes
        return png


@app.get("/api/logo")
def store_logo(store: str = "", debug: str = ""):
    domain = store_domain(store[:100])
    if debug:  # a plain-words report of what happened, for when a logo doesn't show
        trace = []
        png = fetch_logo(domain, trace, fresh=True) if domain else None
        return JSONResponse({"stores_known": len(STORES), "store": store[:100], "website": domain, "tries": trace,
                             "result": ("icon found" if png else "no usable icon came back") if domain else
                                       "that store is not listed in stores.json (or stores.json did not load)"})
    png = fetch_logo(domain) if domain else None
    if not png:
        return Response(status_code=404, headers={"Cache-Control": "private, max-age=300"})
    return Response(png, media_type="image/png", headers={"Cache-Control": "private, max-age=86400"})


def clean_fields(date, payee, amount, check_number, memo):
    """The same rules for a new receipt and for an edited one."""
    if not (math.isfinite(amount) and 0 <= amount < 1e9):
        raise HTTPException(400, "Amount must be a normal positive number")
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Date must look like 2026-09-29")
    payee, check_number, memo = payee.strip()[:100], check_number.strip()[:30], memo.strip()[:200]
    if not payee:
        raise HTTPException(400, "Store name is required")
    return payee, round(amount, 2), check_number, memo


@app.post("/api/checks")
def add_check(
    date: str = Form(...), payee: str = Form(...), amount: float = Form(...),
    check_number: str = Form(""), memo: str = Form(""),
    front: UploadFile = File(...), back: UploadFile = File(None),
):
    payee, amount, check_number, memo = clean_fields(date, payee, amount, check_number, memo)
    cid = str(uuid.uuid4())
    parts = {}
    for side, f in (("front", front), ("back", back)):
        if f is None:
            continue
        blob = f.file.read()
        if len(blob) > MAX_BYTES:
            raise HTTPException(413, "Image over 10 MB")
        img = open_image(blob)
        parts[side] = jpeg(img, 2400, 80)  # tall enough that a long receipt stays readable
        if side == "front":
            parts["thumb"] = jpeg(img, 480, 70)
    for name, data in parts.items():
        put(f"images/{cid}-{name}.enc", fernet.encrypt(data))
    rec = dict(id=cid, date=date, payee=payee.strip(), amount=round(amount, 2),
               check_number=check_number.strip(), memo=memo.strip(),
               has_back="back" in parts, created=datetime.now(timezone.utc).isoformat())
    recs = load_index()
    recs.append(rec)
    save_index(recs)
    return rec


@app.put("/api/checks/{cid}")
def edit_check(cid: str, date: str = Form(...), payee: str = Form(...), amount: float = Form(...),
               check_number: str = Form(""), memo: str = Form("")):
    """Change a receipt's details. The photos are not touched."""
    cid = check_id(cid)
    payee, amount, check_number, memo = clean_fields(date, payee, amount, check_number, memo)
    recs = load_index()
    for r in recs:
        if r["id"] == cid:
            r.update(date=date, payee=payee, amount=amount, check_number=check_number, memo=memo)
            save_index(recs)
            return r
    raise HTTPException(404, "Not found")


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
