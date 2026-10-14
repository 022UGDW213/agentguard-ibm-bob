# AgentGuard Java client SDK

A lightweight Java client for AgentGuard — no runtime dependencies, just the
JDK (11+). It does two things:

1. **Capability tokens** — mint and verify HMAC-SHA256 tokens that are
   wire-compatible with the Python `agentguard.tokens` module. A token minted
   in Java verifies in Python and vice versa, because both sides use the exact
   same canonical JSON (`json.dumps(payload, sort_keys=True)` byte-for-byte).
2. **Policy-check HTTP client** — talk to a running AgentGuard demo
   (`POST /api/guest`, `POST /api/login`, `GET /api/me`, `POST /check`).

## Build

```bash
cd java
mvn -q compile        # or: javac -d target/classes $(find src/main/java -name '*.java')
```

## Run the tests

```bash
javac -d target/classes $(find src/main/java -name '*.java')
javac -cp target/classes -d target/test-classes $(find src/test/java -name '*.java')
java -cp target/classes:target/test-classes com.agentguard.AgentGuardTest
# All Java SDK tests passed.
```

The Python suite also runs a cross-language interop test
(`tests/test_java_interop.py`, skipped when no JDK is installed): it mints a
token in Java and verifies it in Python, then mints in Python and verifies in
Java.

## Usage

```java
import com.agentguard.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

byte[] secret = "shared-secret".getBytes(StandardCharsets.UTF_8);

// 1. Mint a token locally (no server needed).
String token = CapabilityToken.mint(
        secret, "agent-7", List.of("tool:fs_read"), 3600);

// 2. Verify one (e.g. a token minted by the Python service).
CapabilityToken cap = CapabilityToken.verify(secret, token);
System.out.println(cap.subject() + " " + cap.scopes());

// 3. Ask the live policy engine about a tool call.
try (AgentGuardClient client =
        new AgentGuardClient("https://agentguard-demo.o22ugdw213.network")) {
    String guestToken = client.guest();                       // one click, no signup
    Decision d = client.check("read_file", "notes.txt", guestToken);
    System.out.println(d);                                    // ALLOW: ...
    Decision evil = client.check("read_file", "/etc/passwd", guestToken);
    System.out.println(evil);                                 // DENY: ...
}
```

## Layout

```
src/main/java/com/agentguard/
  CapabilityToken.java  — mint/verify, canonical JSON, constant-time compare
  AgentGuardClient.java — java.net.http client for /api/guest, /api/login,
                          /api/me, /check
  Decision.java         — allow/deny + reason
  Json.java             — minimal JSON (Python-compatible escaping + parser)
  TokenException.java
src/test/java/com/agentguard/
  AgentGuardTest.java   — framework-free tests (run via main)
```
