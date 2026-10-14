package com.agentguard;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Self-contained tests for the Java SDK — no test framework needed.
 *
 * <p>Run: {@code java -cp <classes> com.agentguard.AgentGuardTest}
 *
 * <p>Modes for the cross-language interop test:
 * <ul>
 *   <li>{@code print-token <secret>} — print a deterministic token.</li>
 *   <li>{@code verify-token <secret> <token>} — exit 0 iff the token verifies.</li>
 *   <li>{@code verify-token-at <secret> <token> <nowEpoch>} — same, with an
 *       explicit clock (for fixed test vectors).</li>
 * </ul>
 */
public final class AgentGuardTest {

    static final byte[] SECRET = "interop-test-secret".getBytes(StandardCharsets.UTF_8);
    // Fixed vector so Java and Python can compare byte-for-byte.
    static final long IAT = 1_700_000_000L;
    static final long EXP = 1_700_003_600L;
    static final String JTI = "0123456789abcdef";

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("print-token")) {
            byte[] secret = args[1].getBytes(StandardCharsets.UTF_8);
            System.out.println(CapabilityToken.mint(
                    secret, "agent-7",
                    Arrays.asList("tool:fs_read", "tool:fs_write:path=/tmp/*"),
                    IAT, EXP, JTI));
            return;
        }
        if (args.length == 3 && args[0].equals("verify-token")) {
            byte[] secret = args[1].getBytes(StandardCharsets.UTF_8);
            try {
                CapabilityToken cap = CapabilityToken.verify(secret, args[2]);
                System.out.println("OK sub=" + cap.subject()
                        + " scopes=" + cap.scopes());
            } catch (TokenException e) {
                System.out.println("FAIL " + e.getMessage());
                System.exit(1);
            }
            return;
        }
        if (args.length == 4 && args[0].equals("verify-token-at")) {
            byte[] secret = args[1].getBytes(StandardCharsets.UTF_8);
            long now = Long.parseLong(args[3]);
            try {
                CapabilityToken cap = CapabilityToken.verify(secret, args[2], now);
                System.out.println("OK sub=" + cap.subject()
                        + " scopes=" + cap.scopes());
            } catch (TokenException e) {
                System.out.println("FAIL " + e.getMessage());
                System.exit(1);
            }
            return;
        }
        runAll();
    }

    static void runAll() throws Exception {
        mintVerifyRoundTrip();
        tamperedBodyRejected();
        tamperedSignatureRejected();
        wrongSecretRejected();
        expiredRejected();
        deterministicVector();
        System.out.println("All Java SDK tests passed.");
    }

    static void mintVerifyRoundTrip() throws Exception {
        List<String> scopes = Arrays.asList("tool:fs_read", "tool:*");
        String token = CapabilityToken.mint(SECRET, "agent-1", scopes, 3600);
        CapabilityToken cap = CapabilityToken.verify(SECRET, token);
        check(cap.subject().equals("agent-1"), "subject");
        check(cap.scopes().equals(scopes), "scopes");
        check(!cap.isExpired(), "not expired");
        check(cap.tokenId().length() == 16, "token id is 8 random bytes hex");
    }

    static void tamperedBodyRejected() {
        String token = CapabilityToken.mint(SECRET, "agent-1",
                Arrays.asList("tool:fs_read"), 3600);
        String[] parts = token.split("\\.");
        // Flip one char in the body; the signature can no longer match.
        char[] body = parts[0].toCharArray();
        body[5] = body[5] == 'A' ? 'B' : 'A';
        expectFail(SECRET, new String(body) + "." + parts[1], "tampered body");
    }

    static void tamperedSignatureRejected() {
        String token = CapabilityToken.mint(SECRET, "agent-1",
                Arrays.asList("tool:fs_read"), 3600);
        String[] parts = token.split("\\.");
        char[] sig = parts[1].toCharArray();
        sig[2] = sig[2] == 'A' ? 'B' : 'A';
        expectFail(SECRET, parts[0] + "." + new String(sig), "tampered signature");
    }

    static void wrongSecretRejected() {
        String token = CapabilityToken.mint(SECRET, "agent-1",
                Arrays.asList("tool:fs_read"), 3600);
        expectFail("wrong-secret".getBytes(StandardCharsets.UTF_8),
                token, "wrong secret");
    }

    static void expiredRejected() {
        String token = CapabilityToken.mint(SECRET, "agent-1",
                Arrays.asList("tool:fs_read"), IAT, IAT + 10, JTI);
        try {
            CapabilityToken.verify(SECRET, token, IAT + 11);
            throw new AssertionError("expired token verified");
        } catch (TokenException expected) {
            check(expected.getMessage().contains("expired"), "expiry message");
        }
    }

    static void deterministicVector() throws Exception {
        // The canonical body must be byte-identical to Python's
        // json.dumps(payload, sort_keys=True).
        String body = CapabilityToken.canonicalBody(
                IAT, EXP, JTI,
                Arrays.asList("tool:fs_read", "tool:fs_write:path=/tmp/*"),
                "agent-7");
        String expected = "{\"exp\": 1700003600, \"iat\": 1700000000, "
                + "\"jti\": \"0123456789abcdef\", "
                + "\"scopes\": [\"tool:fs_read\", \"tool:fs_write:path=/tmp/*\"], "
                + "\"sub\": \"agent-7\"}";
        check(body.equals(expected), "canonical body matches Python\n got: " + body);
        // And a full token minted here must verify here.
        String token = CapabilityToken.mint(
                SECRET, "agent-7",
                Arrays.asList("tool:fs_read", "tool:fs_write:path=/tmp/*"),
                IAT, EXP, JTI);
        CapabilityToken cap = CapabilityToken.verify(SECRET, token, IAT + 5);
        check(cap.tokenId().equals(JTI), "jti round trip");
    }

    static void expectFail(byte[] secret, String token, String what) {
        try {
            CapabilityToken.verify(secret, token);
        } catch (TokenException expected) {
            return;
        }
        throw new AssertionError(what + " was accepted");
    }

    static void check(boolean cond, String what) {
        if (!cond) throw new AssertionError("failed: " + what);
    }
}
