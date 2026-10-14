package com.agentguard;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal HTTP client for the AgentGuard demo REST API.
 *
 * <ul>
 *   <li>{@code POST /api/guest} — one-click guest capability token.</li>
 *   <li>{@code POST /api/login} — username/password login, returns a token.</li>
 *   <li>{@code GET /api/me} — inspect the caller's token (subject, scopes).</li>
 *   <li>{@code POST /check} — ask the policy engine about a tool call.</li>
 * </ul>
 *
 * <p>Uses only {@code java.net.http} — no dependencies.
 */
public final class AgentGuardClient implements AutoCloseable {

    private static final Duration TIMEOUT = Duration.ofSeconds(30);
    private static final Pattern DECISION_RE =
            Pattern.compile("Decision:\\s*(ALLOW|DENY)");
    private static final Pattern REASON_RE =
            Pattern.compile("<tr><th>reason</th><td>(.*?)</td>",
                    Pattern.DOTALL);

    private final String baseUrl;
    private final HttpClient http;

    public AgentGuardClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /** Mint a one-click guest token. Never throws for bad credentials. */
    public String guest() throws IOException, InterruptedException, TokenException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/guest"))
                .timeout(TIMEOUT)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        Map<String, Object> body = postJson(req);
        return tokenFrom(body);
    }

    /** Log in with the demo credentials; returns the capability token. */
    public String login(String username, String password)
            throws IOException, InterruptedException, TokenException {
        String json = "{\"username\": " + Json.quote(username)
                + ", \"password\": " + Json.quote(password) + "}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/login"))
                .timeout(TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();
        Map<String, Object> body = postJson(req);
        return tokenFrom(body);
    }

    /** Who am I? Verifies the token server-side and returns subject + scopes. */
    public Me me(String token) throws IOException, InterruptedException, TokenException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/me"))
                .timeout(TIMEOUT)
                .header("Authorization", "Bearer " + token)
                .GET()
                .build();
        Map<String, Object> body = getJson(req);
        okOrThrow(body);
        @SuppressWarnings("unchecked")
        List<Object> rawScopes = (List<Object>) body.get("scopes");
        List<String> scopes = new java.util.ArrayList<>();
        for (Object o : rawScopes) scopes.add(String.valueOf(o));
        return new Me(String.valueOf(body.get("subject")), scopes,
                ((Number) body.get("expires_in")).longValue());
    }

    /**
     * Ask the policy engine about a tool call.
     *
     * @param tool   tool name, e.g. {@code "read_file"} or {@code "scan_text"}
     * @param target the tool's target (path or text)
     * @param token  capability token from {@link #guest()} or {@link #login}
     */
    public Decision check(String tool, String target, String token)
            throws IOException, InterruptedException, TokenException {
        String form = "tool=" + enc(tool) + "&target=" + enc(target);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/check"))
                .timeout(TIMEOUT)
                .header("Authorization", "Bearer " + token)
                .header("X-AgentGuard-Fetch", "1")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res = http.send(req,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (res.statusCode() == 401) {
            throw new TokenException("server rejected the token (401)");
        }
        if (res.statusCode() / 100 != 2) {
            throw new IOException("unexpected status " + res.statusCode());
        }
        Matcher dm = DECISION_RE.matcher(res.body());
        if (!dm.find()) {
            throw new IOException("could not parse decision from /check response");
        }
        boolean allow = "ALLOW".equals(dm.group(1));
        String reason = "";
        Matcher rm = REASON_RE.matcher(res.body());
        if (rm.find()) {
            reason = rm.group(1).replaceAll("<[^>]+>", "").trim();
        }
        return new Decision(allow, reason);
    }

    @Override
    public void close() {
        http.close();
    }

    /** Subject + scopes as reported by {@code GET /api/me}. */
    public static final class Me {
        public final String subject;
        public final List<String> scopes;
        public final long expiresIn;

        public Me(String subject, List<String> scopes, long expiresIn) {
            this.subject = subject;
            this.scopes = scopes;
            this.expiresIn = expiresIn;
        }
    }

    // -- helpers ----------------------------------------------------------

    private Map<String, Object> postJson(HttpRequest req)
            throws IOException, InterruptedException, TokenException {
        HttpResponse<String> res = http.send(req,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        Map<String, Object> body = Json.object(res.body());
        okOrThrow(body);
        return body;
    }

    private Map<String, Object> getJson(HttpRequest req)
            throws IOException, InterruptedException, TokenException {
        HttpResponse<String> res = http.send(req,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (res.statusCode() == 401) {
            throw new TokenException("server rejected the token (401)");
        }
        Map<String, Object> body = Json.object(res.body());
        okOrThrow(body);
        return body;
    }

    private static void okOrThrow(Map<String, Object> body) throws TokenException {
        if (!Boolean.TRUE.equals(body.get("ok"))) {
            throw new TokenException("request failed: " + body.get("error"));
        }
    }

    private static String tokenFrom(Map<String, Object> body) {
        Object t = body.get("token");
        if (t == null) throw new IllegalStateException("response had no token");
        return String.valueOf(t);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }
}
