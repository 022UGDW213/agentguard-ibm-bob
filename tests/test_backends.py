import os

import pytest

from agentguard.backends import BackendUnavailable, BobShellBackend


def test_bob_backend_reports_missing_binary(monkeypatch):
    monkeypatch.setenv("BOBSHELL_API_KEY", "dummy")
    monkeypatch.setattr("shutil.which", lambda _: None)
    backend = BobShellBackend()
    with pytest.raises(BackendUnavailable, match="not on PATH"):
        backend.generate("hello")


def test_bob_backend_reports_missing_key(monkeypatch):
    monkeypatch.delenv("BOBSHELL_API_KEY", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/bob")
    backend = BobShellBackend(api_key="")
    with pytest.raises(BackendUnavailable, match="BOBSHELL_API_KEY"):
        backend.check()


def test_bob_backend_uses_env_key(monkeypatch):
    monkeypatch.setenv("BOBSHELL_API_KEY", "env-key-123")
    assert BobShellBackend().api_key == "env-key-123"
    assert BobShellBackend(api_key="explicit").api_key == "explicit"


@pytest.mark.skipif(os.environ.get("BOBSHELL_API_KEY", "") == "",
                    reason="needs a real Bob API key + `bob` CLI")
def test_bob_backend_live_generate():
    # Only runs when the human operator configured Bob Shell for real.
    out = BobShellBackend().generate("Reply with exactly: ok")
    assert "ok" in out.lower()
