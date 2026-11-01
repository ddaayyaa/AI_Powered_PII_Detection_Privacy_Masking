import os, io, csv, re, time, uuid, hmac, hashlib, secrets, logging, tempfile, zipfile
from pathlib import Path
from datetime import timedelta
import jwt
from xml.etree import ElementTree as ET
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import select, func, text
from .db import Base, engine, Session, User, Document, TextScan, PIIEntity, AuditLog, now
from .detector import detect, doc_risk
from .masking import Masker

JWT_SECRET = os.getenv("JWT_SECRET") or secrets.token_hex(32)  # set JWT_SECRET in production
MAX_FILE = int(os.getenv("MAX_FILE_SIZE", 10 * 1024 * 1024))
TMP = Path(os.getenv("TMP_DIR", tempfile.gettempdir())) / "pii_sanitized"; TMP.mkdir(parents=True, exist_ok=True)
RETENTION = int(os.getenv("RETENTION_DAYS", 1))
ALLOWED = {".txt", ".csv", ".docx", ".pdf", ".xlsx"}
STRATS = "FULL|PARTIAL|CHAR|TOKEN|SYNTHETIC|HASH"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s"); log = logging.getLogger("pii")  # never log content

Base.metadata.create_all(engine)
app = FastAPI(title="AI-Powered PII Detection & Privacy Masking", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8000").split(","),
                   allow_methods=["*"], allow_headers=["*"])

_hits: dict = {}
@app.middleware("http")
async def guard(request: Request, call_next):
    t0, ip = time.time(), request.client.host if request.client else "?"
    w = [x for x in _hits.get(ip, []) if t0 - x < 60]; w.append(t0); _hits[ip] = w
    if len(w) > int(os.getenv("RATE_LIMIT_PER_MIN", 120)):
        return JSONResponse({"success": False, "error": {"code": "RATE_LIMITED", "message": "Too many requests."}}, 429)
    if int(request.headers.get("content-length") or 0) > MAX_FILE + 65536:
        return JSONResponse({"success": False, "error": {"code": "TOO_LARGE", "message": "Request too large."}}, 413)
    resp = await call_next(request)
    log.info("%s %s %s %.0fms", request.method, request.url.path, resp.status_code, (time.time() - t0) * 1000)
    return resp

@app.exception_handler(HTTPException)
async def http_err(_, e): return JSONResponse({"success": False, "error": {"code": str(e.detail).split(":")[0], "message": str(e.detail).split(":", 1)[-1].strip()}}, e.status_code)
@app.exception_handler(Exception)
async def any_err(_, e): return JSONResponse({"success": False, "error": {"code": "INTERNAL_ERROR", "message": "Unexpected error."}}, 500)

# ---------- security ----------
def hash_pw(p: str, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(p.encode(), salt=salt, n=2**14, r=8, p=1).hex()
def check_pw(p, stored):
    s, h = stored.split("$"); return hmac.compare_digest(hash_pw(p, bytes.fromhex(s)).split("$")[1], h)
def token(u): return jwt.encode({"sub": u.id, "role": u.role, "exp": now() + timedelta(hours=8)}, JWT_SECRET, "HS256")
bearer = HTTPBearer(auto_error=False)
def user(c: HTTPAuthorizationCredentials = Depends(bearer)):
    try: return jwt.decode(c.credentials, JWT_SECRET, ["HS256"])
    except Exception: raise HTTPException(401, "UNAUTHORIZED: Missing or invalid token.")
def need(*roles):
    def dep(u=Depends(user)):
        if u["role"] not in roles and u["role"] != "ADMIN": raise HTTPException(403, "FORBIDDEN: Insufficient role.")
        return u
    return dep
ANALYST = need("ANALYST"); ANY = need("ANALYST", "VIEWER")

def audit(uid_, action, doc=None, det=0, msk=0, risk="LOW", status="ok"):
    with Session() as s: s.add(AuditLog(user_id=uid_, document_id=doc, action=action, detected=det, masked=msk, risk_level=risk, status=status)); s.commit()

# ---------- schemas ----------
class Cred(BaseModel): email: str = Field(max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"); password: str = Field(min_length=8, max_length=128)
class TextReq(BaseModel):
    text: str = Field(max_length=500_000)
    mode: str = Field("HYBRID", pattern="^(HYBRID|REGEX_ONLY|NLP_ONLY)$")
    strategy: str = Field("FULL", pattern=f"^({STRATS})$")
    threshold: float = Field(0.5, ge=0, le=1); consistent: bool = True

# ---------- auth ----------
@app.post("/api/auth/register")
def register(c: Cred):
    with Session() as s:
        if s.scalar(select(User).where(User.email == c.email.lower())): raise HTTPException(409, "EMAIL_EXISTS: Account already exists.")
        first = s.scalar(select(func.count(User.id))) == 0
        u = User(email=c.email.lower(), password_hash=hash_pw(c.password), role="ADMIN" if first else "ANALYST"); s.add(u); s.commit()
        return {"access_token": token(u), "role": u.role}
@app.post("/api/auth/login")
def login(c: Cred):
    with Session() as s:
        u = s.scalar(select(User).where(User.email == c.email.lower()))
        if not u or not check_pw(c.password, u.password_hash): raise HTTPException(401, "BAD_CREDENTIALS: Invalid email or password.")
        return {"access_token": token(u), "role": u.role}

# ---------- scanning ----------
def summarize(ents):
    return {"total_entities": len(ents), **{f"{r.lower()}_risk": sum(e.risk == r for e in ents) for r in ("HIGH", "MEDIUM", "LOW")}}

@app.post("/api/scan/text")
def scan_text(r: TextReq, u=Depends(ANALYST)):
    ents = detect(r.text, r.mode, r.threshold)
    score, level = doc_risk(ents)
    masked = Masker(r.strategy, r.consistent).apply(r.text, ents)
    entity_data = [e.to_dict() for e in ents]
    with Session() as s:
        saved = TextScan(owner_id=u["sub"], input_text=r.text, masked_text=masked, entities=entity_data,
                         risk_score=score, risk_level=level, strategy=r.strategy)
        s.add(saved); s.commit(); scan_id = saved.id
    audit(u["sub"], "SCAN_TEXT", det=len(ents), msk=len(ents), risk=level)
    return {"scan_id": scan_id, "status": "completed", "risk_score": score, "risk_level": level, "entities": entity_data,
            "masked_text": masked, "summary": summarize(ents)}

def text_scan_dict(saved):
    entities = saved.entities or []
    return {"id": saved.id, "input_text": saved.input_text, "masked_text": saved.masked_text, "entities": entities,
            "risk_score": saved.risk_score, "risk_level": saved.risk_level, "strategy": saved.strategy,
            "summary": {"total_entities": len(entities), **{f"{r.lower()}_risk": sum(e["risk"] == r for e in entities) for r in ("HIGH", "MEDIUM", "LOW")}},
            "created_at": saved.created_at.isoformat()}

@app.get("/api/scans")
def text_scans(page: int = 1, size: int = 20, u=Depends(ANY)):
    with Session() as s:
        rows = s.scalars(select(TextScan).where(TextScan.owner_id == u["sub"])
                         .order_by(TextScan.created_at.desc()).offset((page - 1) * size).limit(min(size, 100))).all()
        return {"items": [text_scan_dict(row) for row in rows], "page": page}

@app.get("/api/scans/{scan_id}")
def text_scan(scan_id: str, u=Depends(ANY)):
    with Session() as s:
        saved = s.scalar(select(TextScan).where(TextScan.id == scan_id, TextScan.owner_id == u["sub"]))
        if not saved: raise HTTPException(404, "NOT_FOUND: Scan not found.")
        return text_scan_dict(saved)

def validate_upload(name: str, data: bytes):
    if not data:
        raise HTTPException(400, "INVALID_FILE: Empty file upload.")
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED:
        raise HTTPException(415, "UNSUPPORTED_FILE_TYPE: The uploaded file type is not supported.")

    if ext in (".txt", ".csv"):
        if b"\x00" in data:
            raise HTTPException(415, "INVALID_FILE: Binary content detected in text file.")
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(415, "INVALID_FILE: File is not valid UTF-8 text.") from exc
        return

    if ext == ".pdf":
        if not data.startswith(b"%PDF"):
            raise HTTPException(415, "INVALID_FILE: PDF content does not match the expected header.")
        return

    if ext in (".docx", ".xlsx"):
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise HTTPException(415, "INVALID_FILE: Archive structure is invalid.")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if ext == ".docx" and "word/document.xml" not in names:
                raise HTTPException(415, "INVALID_FILE: DOCX archive is missing the document XML.")
            if ext == ".xlsx" and "xl/workbook.xml" not in names:
                raise HTTPException(415, "INVALID_FILE: XLSX archive is missing the workbook XML.")
        return

    raise HTTPException(415, "UNSUPPORTED_FILE_TYPE: The uploaded file type is not supported.")


def extract(name: str, data: bytes) -> str:
    ext = Path(name).suffix.lower()
    if ext in (".txt", ".csv"): return data.decode("utf-8-sig", "replace")
    if ext == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                xml = zf.read("word/document.xml")
            root = ET.fromstring(xml)
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            paras = []
            for p in root.findall(".//w:p", ns):
                texts = [t.text for t in p.findall(".//w:t", ns) if t.text]
                if texts:
                    paras.append("".join(texts))
            return "\n".join(paras)
        except Exception:
            return ""
    if ext == ".pdf":
        from pypdf import PdfReader; return "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(data)).pages)
    if ext == ".xlsx":
        import openpyxl; wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        return "\n".join(",".join("" if v is None else str(v) for v in row) for ws in wb for row in ws.iter_rows(values_only=True))
    raise HTTPException(415, "UNSUPPORTED_FILE_TYPE: The uploaded file type is not supported.")

MAGIC = {".pdf": b"%PDF", ".docx": b"PK", ".xlsx": b"PK"}
@app.post("/api/scan/document")
async def scan_doc(file: UploadFile = File(...), strategy: str = Form("FULL"), mode: str = Form("HYBRID"), u=Depends(ANALYST)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED: raise HTTPException(415, "UNSUPPORTED_FILE_TYPE: The uploaded file type is not supported.")
    if strategy not in STRATS.split("|") or mode not in ("HYBRID", "REGEX_ONLY", "NLP_ONLY"): raise HTTPException(422, "INVALID_OPTION: Bad strategy or mode.")
    data = await file.read(MAX_FILE + 1)
    if len(data) > MAX_FILE: raise HTTPException(413, "FILE_TOO_LARGE: File exceeds the size limit.")
    validate_upload(file.filename or "", data)
    if ext in MAGIC and not data.startswith(MAGIC[ext]): raise HTTPException(415, "INVALID_FILE: Content does not match extension.")
    text = extract(file.filename, data)
    ents = detect(text, mode); score, level = doc_risk(ents)
    out = f"{uuid.uuid4().hex}.txt"; (TMP / out).write_text(Masker(strategy).apply(text, ents), encoding="utf-8")  # random name, no user input in path
    with Session() as s:
        d = Document(owner_id=u["sub"], filename=Path(file.filename).name[:255], size=len(data), risk_score=score, risk_level=level, strategy=strategy, output_name=out)
        d.entities = [PIIEntity(type=e.type, start=e.start, end=e.end, confidence=e.confidence, method=e.method, risk=e.risk) for e in ents]
        s.add(d); s.commit(); did = d.id
    audit(u["sub"], "SCAN_DOCUMENT", did, len(ents), len(ents), level)
    return {"document_id": did, "status": "completed", "risk_score": score, "risk_level": level, "summary": summarize(ents)}

# ---------- documents / entities ----------
def doc_dict(d): return {"id": d.id, "filename": d.filename, "size": d.size, "status": d.status, "risk_score": d.risk_score,
                         "risk_level": d.risk_level, "strategy": d.strategy, "entity_count": len(d.entities), "created_at": d.created_at.isoformat()}
@app.get("/api/documents")
def documents(page: int = 1, size: int = 20, q: str = "", risk: str = "", u=Depends(ANY)):
    with Session() as s:
        st = select(Document).order_by(Document.created_at.desc())
        if q: st = st.where(Document.filename.ilike(f"%{q}%"))
        if risk: st = st.where(Document.risk_level == risk.upper())
        rows = s.scalars(st.offset((page - 1) * size).limit(min(size, 100))).all()
        return {"items": [doc_dict(d) for d in rows], "page": page}
def get_doc(s, id_):
    d = s.get(Document, id_)
    if not d: raise HTTPException(404, "NOT_FOUND: Document not found.")
    return d
@app.get("/api/documents/{id_}")
def document(id_: str, u=Depends(ANY)):
    with Session() as s: return doc_dict(get_doc(s, id_))
@app.get("/api/documents/{id_}/entities")
def entities(id_: str, u=Depends(ANY)):
    with Session() as s:
        return [{"id": e.id, "type": e.type, "start": e.start, "end": e.end, "confidence": e.confidence, "method": e.method, "risk": e.risk, "status": e.status} for e in get_doc(s, id_).entities]
@app.get("/api/documents/{id_}/download")
def download(id_: str, u=Depends(ANALYST)):
    with Session() as s: d = get_doc(s, id_); name = d.output_name
    p = TMP / (name or "")
    if not name or not p.is_file(): raise HTTPException(410, "EXPIRED: Sanitized file no longer available.")
    audit(u["sub"], "DOWNLOAD", id_)
    return FileResponse(p, filename=f"sanitized_{Path(d.filename).stem}.txt", media_type="text/plain")
def set_status(id_, st, u):
    with Session() as s:
        e = s.get(PIIEntity, id_)
        if not e: raise HTTPException(404, "NOT_FOUND: Entity not found.")
        e.status = st; s.commit()
    audit(u["sub"], f"ENTITY_{st.upper()}", None); return {"id": id_, "status": st}
@app.post("/api/entities/{id_}/approve")
def approve(id_: str, u=Depends(ANALYST)): return set_status(id_, "accepted", u)
@app.post("/api/entities/{id_}/reject")
def reject(id_: str, u=Depends(ANALYST)): return set_status(id_, "rejected", u)

# ---------- analytics / audit / health ----------
@app.get("/api/analytics/summary")
def analytics(u=Depends(ANY)):
    with Session() as s:
        by = lambda col: dict(s.execute(select(col, func.count()).select_from(PIIEntity).group_by(col)).all())
        return {"documents": s.scalar(select(func.count(Document.id))), "entities": s.scalar(select(func.count(PIIEntity.id))),
                "by_type": by(PIIEntity.type), "by_risk": by(PIIEntity.risk), "by_method": by(PIIEntity.method),
                "avg_confidence": round(s.scalar(select(func.avg(PIIEntity.confidence))) or 0, 3)}
@app.get("/api/audit-logs")
def audit_logs(page: int = 1, size: int = 50, u=Depends(need())):
    with Session() as s:
        rows = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).offset((page - 1) * size).limit(min(size, 200))).all()
        return [{"timestamp": a.timestamp.isoformat(), "user_id": a.user_id, "document_id": a.document_id, "action": a.action,
                 "detected": a.detected, "masked": a.masked, "risk_level": a.risk_level, "status": a.status} for a in rows]

@app.get("/api/db/health")
def db_health():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "database": engine.url.render_as_string(hide_password=True), "dialect": engine.dialect.name}
    except Exception as exc:
        return {"status": "error", "database": engine.url.render_as_string(hide_password=True), "dialect": engine.dialect.name, "error": str(exc)}

@app.get("/api/health")
def health():
    cutoff = time.time() - RETENTION * 86400
    for f in TMP.iterdir():  # retention: purge expired sanitized files
        if f.stat().st_mtime < cutoff: f.unlink(missing_ok=True)
    return {"status": "ok", "database": db_health()}

app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="ui")
