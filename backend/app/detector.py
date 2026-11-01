"""Hybrid PII detector: regex layer + contextual rules + optional spaCy NER, with conflict resolution."""
import re
from dataclasses import dataclass, asdict

RISK = {**{t: "HIGH" for t in ("AADHAAR_NUMBER", "PAN_NUMBER", "PASSPORT_NUMBER", "CREDIT_CARD", "PASSWORD", "API_KEY",
        "ACCESS_TOKEN", "SSN", "CVV", "BANK_ACCOUNT")},
        **{t: "MEDIUM" for t in ("PHONE_NUMBER", "EMAIL", "ADDRESS", "EMPLOYEE_ID", "PERSON_NAME", "UPI_ID", "IFSC_CODE",
        "DATE_OF_BIRTH", "VEHICLE_NUMBER", "GPS_COORDINATES", "IP_ADDRESS", "MAC_ADDRESS")}}  # others -> LOW

def luhn(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(d) <= 19: return False
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2: x = x * 2 - 9 if x > 4 else x * 2
        t += x
    return t % 10 == 0

# (type, regex, group, confidence, explanation, validator)
REGEX = [
    ("EMAIL", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", 0, .99, "Pattern matched email format.", None),
    ("UPI_ID", r"\b[\w.-]{2,}@(?:upi|okaxis|okhdfcbank|oksbi|ybl|paytm|ibl|axl)\b", 0, .97, "Pattern matched UPI handle.", None),
    ("PAN_NUMBER", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0, .98, "Pattern matched PAN format (5 letters, 4 digits, 1 letter).", None),
    ("AADHAAR_NUMBER", r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)", 0, .92, "12-digit number matched Aadhaar format.", None),
    ("CREDIT_CARD", r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", 0, .96, "Digit sequence passed Luhn checksum.", luhn),
    ("IFSC_CODE", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0, .95, "Pattern matched IFSC format.", None),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", 0, .93, "Pattern matched US SSN format.", None),
    ("PHONE_NUMBER", r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)", 0, .93, "Pattern matched Indian mobile number.", None),
    ("PHONE_NUMBER", r"(?<!\d)(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)", 0, .85, "Pattern matched US phone number.", None),
    ("IP_ADDRESS", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", 0, .95, "Pattern matched IPv4 address.", None),
    ("MAC_ADDRESS", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", 0, .95, "Pattern matched MAC address.", None),
    ("URL", r"https?://[^\s<>\"']+", 0, .95, "Pattern matched URL.", None),
    ("API_KEY", r"\b(?:sk|pk|ghp|AKIA)[-_A-Za-z0-9]{16,}\b", 0, .9, "Token prefix and length match API key format.", None),
    ("VEHICLE_NUMBER", r"\b[A-Z]{2}\d{2}[A-Z]{1,2}\d{4}\b", 0, .9, "Pattern matched Indian vehicle registration.", None),
    ("GPS_COORDINATES", r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}", 0, .9, "Pattern matched latitude/longitude pair.", None),
]
NAME_TOKEN = r"[A-Z][a-z]+(?:['’-][A-Z][a-z]+)?"
_N = rf"{NAME_TOKEN}(?:\s+{NAME_TOKEN}){{0,2}}"
CONTEXT = [  # keyword-driven rules; the sensitive value is capture group 1
    ("PERSON_NAME", rf"\b(?:Mr|Mrs|Ms|Dr|Shri|Smt)\.?\s+({_N})", .88, "Honorific precedes a capitalised name."),
    ("PERSON_NAME", rf"(?i:contact|call|name is|hi|dear|regards|attn:?)\s+({_N})\b", .86, "Name follows a contact/greeting keyword."),
    ("PERSON_NAME", rf"\b({_N})(?=\s(?:is|was|works|worked|lives|lived|studies|studying|joined|left|called|said|visited|met|came|has|have|will|can)\b)", .84, "Capitalised name acts as the subject of a verb."),
    ("PERSON_NAME", rf"(?i:\b(?:my|our|his|her|their|student|employee|colleague|friend)\s+(?:name|name is)\s+({_N}))", .85, "Name follows a personal-label keyword."),
    ("PASSWORD", r"(?i)\b(?:password|passwd|pwd)\s*(?:is|:|=)\s*(\S+)", .92, "Value follows a password keyword."),
    ("PASSPORT_NUMBER", r"(?i)passport\D{0,15}([A-Z]\d{7})\b", .93, "Passport keyword near passport-format value."),
    ("EMPLOYEE_ID", r"(?i)(?:employee id|emp\.? ?id|emp no\.?)\W{0,3}([A-Z0-9-]{3,12})", .88, "Value follows an employee-ID keyword."),
    ("BANK_ACCOUNT", r"(?i)(?:account(?: number| no\.?)?|a/c)\W{0,4}(\d{9,18})", .9, "Digits follow a bank-account keyword."),
    ("CVV", r"(?i)\bcvv\W{0,3}(\d{3,4})\b", .95, "Digits follow a CVV keyword."),
    ("ZIP_CODE", r"(?i)(?:pin ?code|zip(?: code)?|postal code)\W{0,3}(\d{5,6})\b", .88, "Digits follow a postal-code keyword."),
    ("DATE_OF_BIRTH", r"(?i)(?:dob|date of birth|born on)\W{0,3}(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})", .93, "Date follows a date-of-birth keyword."),
    ("AGE", r"(?i)\baged?\s+(\d{1,3})\b", .8, "Number follows an age keyword."),
    ("GENDER", r"(?i)gender\W{0,3}(male|female|other)\b", .9, "Value follows a gender keyword."),
]
STOP = {"The", "His", "Her", "This", "That", "It", "He", "She", "They", "We", "My", "Our", "You", "Please", "Thanks", "Hello"}

@dataclass
class Entity:
    text: str; type: str; start: int; end: int; confidence: float; method: str; risk: str; explanation: str
    def to_dict(self): return asdict(self)

_nlp, _nlp_tried = None, False
def _load_nlp(model="en_core_web_sm"):
    global _nlp, _nlp_tried
    if not _nlp_tried:
        _nlp_tried = True
        try:
            import spacy; _nlp = spacy.load(model)
        except Exception: _nlp = None
    return _nlp

def _mk(t, s, e, text, c, m, why): return Entity(text[s:e], t, s, e, c, m, RISK.get(t, "LOW"), why)

def detect_regex(text):
    out = []
    for t, rx, g, c, why, val in REGEX:
        for m in re.finditer(rx, text):
            if val and not val(m.group(g)): continue
            out.append(_mk(t, m.start(g), m.end(g), text, c, "REGEX", why))
    return out

def detect_context(text):
    out = []
    for t, rx, c, why in CONTEXT:
        for m in re.finditer(rx, text):
            if t == "PERSON_NAME" and m.group(1).split()[0] in STOP: continue
            out.append(_mk(t, m.start(1), m.end(1), text, c, "CONTEXT", why))
    for n in {e.text for e in out if e.type == "PERSON_NAME"}:  # propagate known names to every occurrence
        for m in re.finditer(r"\b" + re.escape(n) + r"\b", text):
            out.append(_mk("PERSON_NAME", m.start(), m.end(), text, .8, "CONTEXT", "Repeat of a name already identified in this text."))
    return out

def detect_nlp(text, model="en_core_web_sm"):
    nlp = _load_nlp(model)
    if not nlp: return []
    out = []
    for i in range(0, len(text), 50000):  # chunked processing for large inputs
        for ent in nlp(text[i:i + 50000]).ents:
            if ent.label_ == "PERSON" and ent.text.split()[0] not in STOP:
                out.append(_mk("PERSON_NAME", i + ent.start_char, i + ent.end_char, text, .9,
                               "NER", "spaCy NER model classified this span as PERSON."))
    return out

def resolve(ents):
    """Remove duplicates/overlaps: higher confidence wins, then longer span."""
    keep = []
    for e in sorted(ents, key=lambda e: (-e.confidence, -(e.end - e.start))):
        if all(e.end <= k.start or e.start >= k.end for k in keep): keep.append(e)
    return sorted(keep, key=lambda e: e.start)

def detect(text, mode="HYBRID", threshold=0.5):
    ents = []
    if mode in ("HYBRID", "REGEX_ONLY"): ents += detect_regex(text) + detect_context(text)
    if mode in ("HYBRID", "NLP_ONLY"): ents += detect_nlp(text)
    return [e for e in resolve(ents) if e.confidence >= threshold]

W = {"HIGH": 1.0, "MEDIUM": .5, "LOW": .2}
def doc_risk(ents):
    """Weighted sensitivity x confidence x frequency, squashed to 0-100."""
    import math
    s = sum(W[e.risk] * e.confidence for e in ents)
    score = round(100 * (1 - math.exp(-s / 3)), 1)
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    return score, (level if ents else "LOW")
