import hashlib, io, json, math, os, secrets, time, uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
import pyotp
from PIL import Image, ImageOps
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
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
                                    response_checksum_validation="when_required"))
else:
    DATA.mkdir(exist_ok=True)


def put(key, blob):
    if BUCKET:
        s3.put_object(Bucket=BUCKET, Key=key, Body=blob)
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
        s3.delete_object(Bucket=BUCKET, Key=key)
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


TOTP = pyotp.TOTP(os.environ["TOTP_SECRET"])
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
    if path == "/login":
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
    user_ok = secrets.compare_digest(username.encode(), USER.encode())
    pass_ok = secrets.compare_digest(password.encode(), PASSWORD.encode())
    code_ok = TOTP.verify(code, valid_window=1) and code != last_code[0]
    if not (user_ok and pass_ok and code_ok):
        fails.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "Wrong username, password, or code")
    fails.pop(ip, None)
    last_code[0] = code
    resp = JSONResponse({"ok": True})
    resp.set_cookie("session", signer.dumps("ok"), max_age=SESSION_SECONDS,
                    httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return resp


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
