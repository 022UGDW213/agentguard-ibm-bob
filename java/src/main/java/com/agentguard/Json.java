package com.agentguard;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code json.dumps(..., ensure_ascii=True)} byte-for-byte, plus a small
 * recursive-descent parser for the flat response shapes this SDK reads.
 *
 * <p>Escaping: quotes, backslashes, control characters, and every non-ASCII
 * character become backslash-u hex escapes, exactly like Python.
 *
 * <p>Only the JDK is used — no JSON library dependency.
 */
final class Json {

    private Json() {}

    /**
     * Quote a string exactly the way Python's {@code json.dumps} does with
     * ASCII-only output: quotes, backslashes and control characters are
     * escaped, and every non-ASCII char becomes a backslash-u hex escape.
     */
    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7F) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    /** Parse a JSON object or array. Returns Map, List, String, Long/Double, Boolean, or null. */
    @SuppressWarnings("unchecked")
    static Object parse(String text) {
        Parser p = new Parser(text);
        Object v = p.value();
        p.ws();
        if (p.pos != text.length()) {
            throw new IllegalArgumentException("trailing data after JSON value");
        }
        return v;
    }

    static Map<String, Object> object(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) v;
    }

    // -- tiny recursive-descent parser ------------------------------------

    private static final class Parser {
        final String s;
        int pos;

        Parser(String s) { this.s = s; }

        void ws() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object value() {
            ws();
            if (pos >= s.length()) throw new IllegalArgumentException("unexpected end of JSON");
            char c = s.charAt(pos);
            switch (c) {
                case '{': return obj();
                case '[': return arr();
                case '"': return str();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default: return num();
            }
        }

        void expect(String lit) {
            if (!s.startsWith(lit, pos)) throw new IllegalArgumentException("bad literal at " + pos);
            pos += lit.length();
        }

        Map<String, Object> obj() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; // {
            ws();
            if (peek() == '}') { pos++; return m; }
            while (true) {
                ws();
                String k = str();
                ws();
                if (peek() != ':') throw new IllegalArgumentException("expected ':' at " + pos);
                pos++;
                m.put(k, value());
                ws();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; return m; }
                throw new IllegalArgumentException("expected ',' or '}' at " + pos);
            }
        }

        List<Object> arr() {
            List<Object> l = new ArrayList<>();
            pos++; // [
            ws();
            if (peek() == ']') { pos++; return l; }
            while (true) {
                l.add(value());
                ws();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; return l; }
                throw new IllegalArgumentException("expected ',' or ']' at " + pos);
            }
        }

        char peek() {
            if (pos >= s.length()) throw new IllegalArgumentException("unexpected end of JSON");
            return s.charAt(pos);
        }

        String str() {
            if (peek() != '"') throw new IllegalArgumentException("expected string at " + pos);
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) throw new IllegalArgumentException("unterminated string");
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= s.length()) throw new IllegalArgumentException("bad escape");
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > s.length()) throw new IllegalArgumentException("bad \\u escape");
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            pos += 4;
                            break;
                        default: throw new IllegalArgumentException("bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        Number num() {
            int start = pos;
            while (pos < s.length() && "-+0123456789.eE".indexOf(s.charAt(pos)) >= 0) pos++;
            String t = s.substring(start, pos);
            try {
                return Long.parseLong(t);
            } catch (NumberFormatException e) {
                return Double.parseDouble(t);
            }
        }
    }
}
