"""Masking engine with 6 strategies and session-level consistent mapping (never exposed via API)."""
import hashlib, secrets

NAMES = ["John Smith", "Jane Doe", "Alex Taylor", "Sam Lee", "Chris Brown", "Pat Morgan"]

class Masker:
    def __init__(self, strategy="FULL", consistent=True):
        self.strategy, self.consistent = strategy.upper(), consistent
        self._map, self._n, self._salt = {}, {}, secrets.token_hex(8)

    def _idx(self, e):
        key = (e.type, e.text.lower())
        if self.consistent and key in self._map: return self._map[key]
        self._n[e.type] = self._n.get(e.type, 0) + 1
        if self.consistent: self._map[key] = self._n[e.type]
        return self._n[e.type]

    @staticmethod
    def _partial(e):
        t = e.text
        if e.type == "EMAIL" and "@" in t: u, d = t.split("@", 1); return u[0] + "***@" + d
        if e.type == "PAN_NUMBER": return "XXXXX" + t[5:]
        if len(t) <= 4: return "*" * len(t)
        return "".join("*" if c.isalnum() else c for c in t[:-4]) + t[-4:]

    def one(self, e):
        s = self.strategy
        if s == "FULL": return f"[{e.type}]"
        if s == "PARTIAL": return self._partial(e)
        if s == "CHAR": return "*" * len(e.text)
        if s == "TOKEN": return f"{e.type.split('_')[0]}_{self._idx(e):03d}"
        if s == "HASH": return "HASH_" + hashlib.sha256((self._salt + e.type + e.text.lower()).encode()).hexdigest()[:6]
        if s == "SYNTHETIC":
            i = self._idx(e)
            return {"PERSON_NAME": NAMES[(i - 1) % len(NAMES)], "EMAIL": f"user{i:03d}@example.com",
                    "PHONE_NUMBER": f"90000{i:05d}", "PAN_NUMBER": f"AAAAA{i:04d}A", "IP_ADDRESS": f"192.0.2.{i % 254 + 1}"}.get(e.type, f"[{e.type}]")
        raise ValueError(f"Unknown strategy {self.strategy}")

    def apply(self, text, ents):
        out, pos = [], 0
        for e in sorted(ents, key=lambda e: e.start):
            out += [text[pos:e.start], self.one(e)]; pos = e.end
        return "".join(out) + text[pos:]
