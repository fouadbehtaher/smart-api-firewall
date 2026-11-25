"""
Deterministic signature pre-filter that runs before the AI check.

Why: the AI check fails open (no API key, quota error or timeout all return
"SAFE"), costs one model call per new payload, and the payload is pasted into
the prompt, so an attacker can try to talk the model into answering "SAFE".
Obvious attacks are now stopped locally; only payloads that pass these checks
go on to the AI.

Limits: this is a short list of classic patterns, not a full WAF rule set.
Anything it does not recognise still depends on the AI verdict.
"""
import re
from typing import List, Optional, Tuple
from urllib.parse import unquote_plus

MAX_DECODE_PASSES = 4
MAX_SCAN_CHARS = 100_000  # bound the work done per request body

_JSON_UNICODE = re.compile(r"\\u([0-9a-fA-F]{4})")

# (label, compiled pattern). Labels match the names used by ai_guard.
SIGNATURES: List[Tuple[str, "re.Pattern[str]"]] = [
    ("SQL_INJECTION", re.compile(r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\b(?:\s|/\*.*?\*/)+)?select\b", re.I)),
    ("SQL_INJECTION", re.compile(r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.I)),
    ("SQL_INJECTION", re.compile(r"\b(?:or|and)\s+\d+\s*=\s*\d+", re.I)),
    ("SQL_INJECTION", re.compile(r";\s*(?:drop|alter|truncate|delete|insert|update)\b", re.I)),
    ("SQL_INJECTION", re.compile(r"\b(?:sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()", re.I)),
    ("SQL_INJECTION", re.compile(r"\binformation_schema\b", re.I)),
    ("XSS_ATTACK", re.compile(r"<\s*script\b", re.I)),
    ("XSS_ATTACK", re.compile(r"\bjavascript\s*:", re.I)),
    ("XSS_ATTACK", re.compile(r"<[^>]{0,200}\bon[a-z]{3,20}\s*=", re.I)),
    ("XSS_ATTACK", re.compile(r"<\s*(?:iframe|object|embed)\b", re.I)),
    ("COMMAND_INJECTION", re.compile(r"(?:;|\|\|?|&&)\s*(?:cat|ls|rm|wget|curl|nc|bash|sh|powershell|whoami|id)\b", re.I)),
    ("COMMAND_INJECTION", re.compile(r"\$\([^)]{1,200}\)|`[^`]{1,200}`")),
    ("COMMAND_INJECTION", re.compile(r"/etc/(?:passwd|shadow)\b", re.I)),
    ("PATH_TRAVERSAL", re.compile(r"(?:\.\./|\.\.\\){2,}")),
]


def normalize(text: str) -> str:
    """URL-decode (bounded) and undo JSON escapes so encoded payloads are visible."""
    current = text[:MAX_SCAN_CHARS]
    for _ in range(MAX_DECODE_PASSES):
        decoded = unquote_plus(current)
        if "\\" in decoded:
            decoded = _JSON_UNICODE.sub(lambda m: chr(int(m.group(1), 16)), decoded.replace("\\/", "/"))
        if decoded == current:
            break
        current = decoded
    return current


def detect_signature(text: Optional[str]) -> Optional[str]:
    """Return the threat label of the first matching signature, or None."""
    if not text:
        return None
    candidate = normalize(text)
    for label, pattern in SIGNATURES:
        if pattern.search(candidate):
            return label
    return None
