"""Cross-language interop: Java-minted tokens verify in Python and vice versa.

Skipped when no JDK is installed. Compiles the java/ SDK with javac into a
temp dir, then runs both directions over a fixed test vector.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from agentguard import tokens as py_tokens

REPO = Path(__file__).resolve().parent.parent
JAVA = REPO / "java"
SECRET = b"interop-test-secret"
SUBJECT = "agent-7"
SCOPES = ["tool:fs_read", "tool:fs_write:path=/tmp/*"]
IAT, EXP, JTI = 1_700_000_000, 1_700_003_600, "0123456789abcdef"

pytestmark = pytest.mark.skipif(
    shutil.which("javac") is None, reason="no JDK installed"
)


@pytest.fixture(scope="module")
def classes(tmp_path_factory):
    out = tmp_path_factory.mktemp("java-classes")
    main = sorted((JAVA / "src/main/java").rglob("*.java"))
    test = sorted((JAVA / "src/test/java").rglob("*.java"))
    subprocess.run(
        ["javac", "-d", str(out)] + [str(p) for p in main + test],
        check=True, capture_output=True, text=True,
    )
    return out


def _java(classes, *args):
    return subprocess.run(
        ["java", "-cp", str(classes), "com.agentguard.AgentGuardTest", *args],
        check=True, capture_output=True, text=True,
    )


def test_java_mints_python_verifies(classes):
    """Token minted by the Java SDK verifies with the Python module."""
    proc = _java(classes, "print-token", SECRET.decode())
    token = proc.stdout.strip()
    assert token.count(".") == 1
    cap = py_tokens.verify(SECRET, token, now=IAT + 5)
    assert cap.subject == SUBJECT
    assert cap.scopes == SCOPES
    assert cap.token_id == JTI
    assert cap.expires_at == EXP
    assert cap.issued_at == IAT


def test_python_mints_java_verifies(classes):
    """Token minted by the Python module verifies with the Java SDK."""
    body_b64, sig_b64 = None, None
    # Rebuild Python's mint deterministically for the fixed vector.
    import base64, hashlib, hmac, json

    payload = {"sub": SUBJECT, "scopes": SCOPES, "iat": IAT, "exp": EXP,
               "jti": JTI}
    body = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(
        hmac.new(SECRET, body.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    token = f"{body}.{sig}"
    # Sanity: Python itself accepts it.
    py_tokens.verify(SECRET, token, now=IAT + 5)
    proc = _java(classes, "verify-token-at", SECRET.decode(), token, str(IAT + 5))
    assert "OK" in proc.stdout
    assert SUBJECT in proc.stdout


def test_java_self_tests(classes):
    proc = _java(classes)
    assert "All Java SDK tests passed." in proc.stdout
