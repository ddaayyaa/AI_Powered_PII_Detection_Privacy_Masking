import os, tempfile
from pathlib import Path

fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)
os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

from fastapi.testclient import TestClient
from app.main import app
from app.detector import detect
from app.masking import Masker
c = TestClient(app)
S = "Rahul Kumar works at ABC Technologies. His email is rahul.kumar@example.com and phone number is 9876543210. His PAN is ABCDE1234F."
def types(t): return {e.type: e.text for e in detect(t, "REGEX_ONLY")}
def test_demo_sentence():
    t = types(S); assert t["PERSON_NAME"] == "Rahul Kumar" and t["EMAIL"] == "rahul.kumar@example.com"
    assert t["PHONE_NUMBER"] == "9876543210" and t["PAN_NUMBER"] == "ABCDE1234F"
def test_card_luhn_and_no_false_positive():
    assert "CREDIT_CARD" in types("Card 4111 1111 1111 1111"); assert "CREDIT_CARD" not in types("ref 1234567890123456")
def test_aadhaar_ifsc_upi(): assert {"AADHAAR_NUMBER", "IFSC_CODE", "UPI_ID"} <= set(types("2345 6789 0123 SBIN0001234 rahul@okaxis"))
def test_full_and_consistency():
    e = detect("Rahul Kumar called Rahul Kumar. Contact Anita Sharma"); m = Masker("TOKEN")
    assert m.apply("Rahul Kumar called Rahul Kumar. Contact Anita Sharma", e).count("PERSON_001") == 2
def test_single_word_subject_names_are_detected():
    text = "Ramu is studying in b-tech college. Dayakar works in Cognizant Company. Dayakar is studying in B-Tech Engineering college."
    names = {e.text for e in detect(text, "REGEX_ONLY") if e.type == "PERSON_NAME"}
    assert "Ramu" in names
    assert "Dayakar" in names
    entities = detect(text, "REGEX_ONLY")
    assert Masker("FULL").apply(text, entities).count("[PERSON_NAME]") == 3
def test_partial(): assert Masker("PARTIAL").apply("9876543210", detect("9876543210")) == "******3210"
def test_auth_flow():
    assert c.post("/api/scan/text", json={"text": S}).status_code == 401
    tok = c.post("/api/auth/register", json={"email": "a@b.co", "password": "password123"}).json()["access_token"]
    H = {"Authorization": f"Bearer {tok}"}
    r = c.post("/api/scan/text", json={"text": S, "mode": "REGEX_ONLY"}, headers=H).json()
    assert "[PAN_NUMBER]" in r["masked_text"] and r["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    personal_text = "Rahul Kumar works at ABC Technologies. His email is rahul.kumar@example.com and phone number is 9876543210. His PAN is ABCDE1234F.\nDayakar is studying in B-Tech Engineering college."
    saved_scan = c.post("/api/scan/text", json={"text": personal_text}, headers=H).json()
    assert "[PERSON_NAME]" in saved_scan["masked_text"].splitlines()[1]
    history = c.get("/api/scans", headers=H).json()["items"]
    assert any(item["id"] == saved_scan["scan_id"] and item["input_text"] == personal_text for item in history)
    assert c.get(f"/api/scans/{saved_scan['scan_id']}", headers=H).json()["masked_text"] == saved_scan["masked_text"]
    other_tok = c.post("/api/auth/register", json={"email": "other@b.co", "password": "password123"}).json()["access_token"]
    other_history = c.get("/api/scans", headers={"Authorization": f"Bearer {other_tok}"}).json()["items"]
    assert other_history == []
    assert c.get(f"/api/scans/{saved_scan['scan_id']}", headers={"Authorization": f"Bearer {other_tok}"}).status_code == 404
    f = c.post("/api/scan/document", files={"file": ("a.txt", S.encode())}, headers=H).json()
    d = c.get(f"/api/documents/{f['document_id']}/download", headers=H); assert d.status_code == 200 and "ABCDE1234F" not in d.text
    assert c.post("/api/scan/document", files={"file": ("a.exe", b"x")}, headers=H).status_code == 415
    assert c.get("/api/audit-logs", headers=H).status_code == 200
