# AI-Powered PII Detection & Privacy Masking
FastAPI + SQLAlchemy + hybrid detection (regex → contextual rules → optional spaCy NER → conflict resolution → confidence/risk scoring) + 6 masking strategies + JWT RBAC + audit log + Chart.js dashboard (served by the backend at `/`).

## Run
```
cd backend && python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install spacy && python -m spacy download en_core_web_sm        # optional NER layer
export JWT_SECRET=$(openssl rand -hex 32)                           # Windows: set JWT_SECRET=...
uvicorn app.main:app --reload          # UI: http://localhost:8000  Swagger: /docs
pytest -q
```
Docker: `cp .env.example .env` (edit secrets) then `docker compose up --build`.
First registered user is ADMIN; later users are ANALYST. Demo: paste the sentence from `sample_data/sample.txt` in Text Scanner.

## Privacy design
Only metadata is stored (type, offsets, confidence, risk); raw PII is never written to the DB, audit log or app logs. Sanitized files use random names and expire after `RETENTION_DAYS`. Masking is irreversible; the pseudonym map lives only in memory per request.

## Limitations
Sanitized output is plain text (no layout-preserving PDF/DOCX rewrite); no OCR; person-name detection is rule-based unless spaCy is installed; rate limiter is in-memory; schema is created with `create_all` (no Alembic); not a legal compliance guarantee (GDPR/DPDP).
