package com.agentguard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 capability tokens, wire-compatible with the Python
 * {@code agentguard.tokens} module.
 *
 * <p>Wire format: {@code base64url(body) + "." + base64url(sig)} where
 * {@code body} is the canonical JSON
 * {@code {"exp": …, "iat": …, "jti": "…", "scopes": […], "sub": "…"}}
 * — byte-identical to Python's {@code json.dumps(payload, sort_keys=True)}
 * (sorted keys, {@code ": "} and {@code ", "} separators, ASCII-escaped
 * strings) — and {@code sig = HMAC-SHA256(secret, body)}.
 *
 * <p>Tokens minted here verify in Python and vice versa; see the
 * cross-language test in {@code AgentGuardTest}.
 */
public final class CapabilityToken {

    private final String subject;
    private final List<String> scopes;
    private final long expiresAt;
    private final String tokenId;
    private final long issuedAt;

    public CapabilityToken(String subject, List<String> scopes, long expiresAt,
                           String tokenId, long issuedAt) {
        this.subject = subject;
        this.scopes = Collections.unmodifiableList(new ArrayList<>(scopes));
        this.expiresAt = expiresAt;
        this.tokenId = tokenId;
        this.issuedAt = issuedAt;
    }

    public String subject() { return subject; }
    public List<String> scopes() { return scopes; }
    public long expiresAt() { return expiresAt; }
    public String tokenId() { return tokenId; }
    public long issuedAt() { return issuedAt; }

    public boolean isExpired() {
        return isExpired(Instant.now().getEpochSecond());
    }

    public boolean isExpired(long nowEpochSeconds) {
        return nowEpochSeconds >= expiresAt;
    }

    // -- minting ----------------------------------------------------------

    /** Mint a token valid for {@code ttlSeconds} from now. */
    public static String mint(byte[] secret, String subject,
                             List<String> scopes, long ttlSeconds) {
        long now = Instant.now().getEpochSecond();
        return mint(secret, subject, scopes, now, now + ttlSeconds, randomId());
    }

    /**
     * Mint with explicit timestamps and id (used by tests so vectors are
     * deterministic and comparable across languages).
     */
    public static String mint(byte[] secret, String subject, List<String> scopes,
                             long issuedAt, long expiresAt, String tokenId) {
        String body = canonicalBody(issuedAt, expiresAt, tokenId, scopes, subject);
        String bodyB64 = b64url(body.getBytes(StandardCharsets.UTF_8));
        byte[] sig = hmac(secret, bodyB64.getBytes(StandardCharsets.US_ASCII));
        return bodyB64 + "." + b64url(sig);
    }

    // -- verification -----------------------------------------------------

    /** Verify a token string; returns the parsed payload or throws. */
    public static CapabilityToken verify(byte[] secret, String token) throws TokenException {
        return verify(secret, token, Instant.now().getEpochSecond());
    }

    public static CapabilityToken verify(byte[] secret, String token, long nowEpochSeconds)
            throws TokenException {
        int dot = token.indexOf('.');
        if (dot < 0) {
            throw new TokenException("malformed token: missing signature part");
        }
        String bodyB64 = token.substring(0, dot);
        String sigB64 = token.substring(dot + 1);
        byte[] expected = hmac(secret, bodyB64.getBytes(StandardCharsets.US_ASCII));
        byte[] actual;
        try {
            actual = Base64.getUrlDecoder().decode(pad(sigB64));
        } catch (IllegalArgumentException e) {
            throw new TokenException("malformed token: bad signature encoding", e);
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new TokenException("invalid signature");
        }
        Map<String, Object> payload;
        try {
            String bodyJson = new String(Base64.getUrlDecoder().decode(pad(bodyB64)),
                    StandardCharsets.UTF_8);
            payload = Json.object(bodyJson);
        } catch (IllegalArgumentException e) {
            throw new TokenException("malformed token: bad payload encoding", e);
        }
        try {
            CapabilityToken cap = new CapabilityToken(
                    str(payload, "sub"),
                    strList(payload, "scopes"),
                    num(payload, "exp"),
                    strOr(payload, "jti", ""),
                    numOr(payload, "iat", 0));
            if (cap.isExpired(nowEpochSeconds)) {
                throw new TokenException("token expired");
            }
            return cap;
        } catch (TokenException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new TokenException("invalid payload: " + e.getMessage(), e);
        }
    }

    // -- canonical encoding (must match Python exactly) -------------------

    /**
     * Build the canonical body. Key order and separators mirror
     * {@code json.dumps(payload, sort_keys=True)}: sorted keys,
     * {@code ": "} after keys, {@code ", "} between items.
     */
    static String canonicalBody(long issuedAt, long expiresAt, String tokenId,
                               List<String> scopes, String subject) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"exp\": ").append(expiresAt);
        sb.append(", \"iat\": ").append(issuedAt);
        sb.append(", \"jti\": ").append(Json.quote(tokenId));
        sb.append(", \"scopes\": [");
        for (int i = 0; i < scopes.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(Json.quote(scopes.get(i)));
        }
        sb.append("]");
        sb.append(", \"sub\": ").append(Json.quote(subject));
        sb.append("}");
        return sb.toString();
    }

    // -- helpers ----------------------------------------------------------

    private static byte[] hmac(byte[] secret, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /** Add back any stripped padding before decoding (tolerates both forms). */
    private static String pad(String s) {
        int m = s.length() % 4;
        if (m == 0) return s;
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < 4 - m; i++) sb.append('=');
        return sb.toString();
    }

    private static String randomId() {
        byte[] b = new byte[8];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(16);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String str(Map<String, Object> m, String key) throws TokenException {
        Object v = m.get(key);
        if (v == null) throw new TokenException("invalid payload: missing '" + key + "'");
        return String.valueOf(v);
    }

    private static String strOr(Map<String, Object> m, String key, String dflt) {
        Object v = m.get(key);
        return v == null ? dflt : String.valueOf(v);
    }

    private static long num(Map<String, Object> m, String key) throws TokenException {
        Object v = m.get(key);
        if (!(v instanceof Number)) throw new TokenException("invalid payload: '" + key + "' not a number");
        return ((Number) v).longValue();
    }

    private static long numOr(Map<String, Object> m, String key, long dflt) {
        Object v = m.get(key);
        return v instanceof Number ? ((Number) v).longValue() : dflt;
    }

    @SuppressWarnings("unchecked")
    private static List<String> strList(Map<String, Object> m, String key) throws TokenException {
        Object v = m.get(key);
        if (!(v instanceof List)) throw new TokenException("invalid payload: '" + key + "' not a list");
        List<String> out = new ArrayList<>();
        for (Object o : (List<Object>) v) out.add(String.valueOf(o));
        return out;
    }
}
