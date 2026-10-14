"""Tests for the AgentGuard Skills API on the Cloudflare worker.

The `workers` runtime module is stubbed so entry.py's pure logic and
request handlers run locally: fake env (in-memory KV), fake requests.
Covers: skills listing, policy-check, token-mint (incl. no-escalation),
token-verify, secret-scan, audit-query, harness-run, and auth gating.
"""

import asyncio
import json
import sys
import types

import pytest


def _install_workers_stub():
    mod = types.ModuleType("workers")

    class FakeResponse:
        def __init__(self, body="", status=200, headers=None):
            self.body = body
            self.status = status
            self.headers = dict(headers or {})

    class FakeEntrypoint:
        def __init__(self):
            self.env = None

    mod.Response = FakeResponse
    mod.WorkerEntrypoint = FakeEntrypoint
    sys.modules["workers"] = mod


_install_workers_stub()

import worker_entry  # noqa: E402  (after stub install)


class FakeKV:
    def __init__(self):
        self.store = {}

    async def get(self, key):
        return self.store.get(key)

    async def put(self, key, value):
        self.store[key] = value


class FakeEnv:
    def __init__(self):
        self.AUDIT_KV = FakeKV()


class FakeRequest:
    def __init__(self, method="GET", url="https://demo/", headers=None,
                 body=""):
        self.method = method
        self.url = url
        self.headers = dict(headers or {})
        self._body = body

    async def text(self):
        return self._body


def _worker(monkeypatch):
    monkeypatch.setenv("AG_DEMO_USER", "demo")
    monkeypatch.setenv("AG_DEMO_PASSWORD", "agentguard")
    monkeypatch.delenv("HMAC_SECRET", raising=False)
    w = worker_entry.Default()
    w.env = FakeEnv()
    return w


def _call(w, method, path, token=None, body=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw = body if isinstance(body, str) else json.dumps(body or {})
    req = FakeRequest(method, f"https://demo{path}", headers, raw)
    return asyncio.run(w.fetch(req))


def _json(resp):
    assert resp.status < 500, resp.body
    return json.loads(resp.body)


def _guest_token(w):
    resp = _call(w, "POST", "/api/guest")
    data = _json(resp)
    assert resp.status == 200 and data["ok"]
    return data["token"]


def test_skills_list_requires_token(w_fix):
    resp = _call(w_fix, "GET", "/api/skills")
    assert resp.status == 401


def test_skills_list(w_fix):
    token = _guest_token(w_fix)
    data = _json(_call(w_fix, "GET", "/api/skills", token=token))
    assert data["ok"]
    names = [s["name"] for s in data["skills"]]
    assert names == ["policy-check", "token-mint", "token-verify",
                     "secret-scan", "audit-query", "harness-run", "trap"]
    for skill in data["skills"]:
        assert skill["path"] and skill["method"] and skill["description"]
        assert "example" in skill and "input_schema" in skill


def test_policy_check_allow_and_deny(w_fix):
    token = _guest_token(w_fix)
    allow = _json(_call(w_fix, "POST", "/api/skills/policy-check",
                        token=token,
                        body={"tool": "read_file",
                              "args": {"path": "welcome.txt"}}))
    assert allow["ok"] and allow["allow"] is True

    deny = _json(_call(w_fix, "POST", "/api/skills/policy-check",
                       token=token,
                       body={"tool": "run_command",
                             "args": {"cmd": "rm -rf /"}}))
    assert deny["ok"] and deny["allow"] is False
    assert deny["reason"]


def test_policy_check_bad_input(w_fix):
    token = _guest_token(w_fix)
    resp = _call(w_fix, "POST", "/api/skills/policy-check", token=token,
                 body={"tool": "read_file"})
    assert resp.status == 400


def test_token_mint_subset_and_escalation_blocked(w_fix):
    token = _guest_token(w_fix)
    ok = _json(_call(w_fix, "POST", "/api/skills/token-mint", token=token,
                     body={"scopes": ["tool:read_file"],
                           "ttl_seconds": 600}))
    assert ok["ok"] and ok["scopes"] == ["tool:read_file"]
    # The minted token actually works.
    check = _json(_call(w_fix, "POST", "/api/skills/policy-check",
                        token=ok["token"],
                        body={"tool": "read_file",
                              "args": {"path": "welcome.txt"}}))
    assert check["allow"] is True

    # Escalation attempt: scope the caller doesn't hold.
    resp = _call(w_fix, "POST", "/api/skills/token-mint", token=token,
                 body={"scopes": ["tool:admin"]})
    assert resp.status == 403


def test_token_verify(w_fix):
    token = _guest_token(w_fix)
    good = _json(_call(w_fix, "POST", "/api/skills/token-verify",
                       token=token, body={"token": token}))
    assert good["ok"] and good["valid"] is True
    assert good["subject"] == "guest"

    bad = _json(_call(w_fix, "POST", "/api/skills/token-verify",
                      token=token, body={"token": "bogus.token"}))
    assert bad["ok"] and bad["valid"] is False


def test_secret_scan(w_fix):
    token = _guest_token(w_fix)
    hit = _json(_call(w_fix, "POST", "/api/skills/secret-scan", token=token,
                      body={"text": "key=AKIAIOSFODNN7EXAMPLE"}))
    assert hit["ok"] and len(hit["findings"]) == 1
    assert hit["findings"][0]["kind"] == "aws_access_key"

    clean = _json(_call(w_fix, "POST", "/api/skills/secret-scan", token=token,
                        body={"text": "nothing to see here"}))
    assert clean["findings"] == []


def test_audit_query_safe_projection(w_fix):
    token = _guest_token(w_fix)
    _call(w_fix, "POST", "/api/skills/policy-check", token=token,
          body={"tool": "read_file", "args": {"path": "welcome.txt"}})
    data = _json(_call(w_fix, "GET", "/api/skills/audit-query?limit=5",
                       token=token))
    assert data["ok"] and len(data["entries"]) >= 1
    for entry in data["entries"]:
        assert set(entry) <= {"ts", "tool", "args", "decision", "reason",
                              "subject"}
    assert data["summary"]["total"] >= 1


def test_harness_run_transcript(w_fix):
    token = _guest_token(w_fix)
    data = _json(_call(w_fix, "POST", "/api/skills/harness-run",
                       token=token, body={}))
    assert data["ok"] and len(data["steps"]) == 4
    decisions = [s["decision"] for s in data["steps"]]
    assert decisions == ["allow", "deny", "allow", "deny"]
    assert data["allowed"] == 2 and data["denied"] == 2
    # The scan step flagged the demo key.
    scan_step = data["steps"][2]
    assert any(f["kind"] == "aws_access_key"
               for f in scan_step["findings"])
    # The escape step was denied with a sandbox reason.
    assert "sandbox" in data["steps"][1]["reason"]


def test_skill_endpoints_require_token(w_fix):
    for method, path in [
        ("POST", "/api/skills/policy-check"),
        ("POST", "/api/skills/token-mint"),
        ("POST", "/api/skills/token-verify"),
        ("POST", "/api/skills/secret-scan"),
        ("GET", "/api/skills/audit-query"),
        ("POST", "/api/skills/harness-run"),
    ]:
        resp = _call(w_fix, method, path, body={})
        assert resp.status == 401, path


@pytest.fixture
def w_fix(monkeypatch):
    return _worker(monkeypatch)
