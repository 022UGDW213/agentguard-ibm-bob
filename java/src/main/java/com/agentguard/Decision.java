package com.agentguard;

/** The outcome of one policy check. */
public final class Decision {
    private final boolean allow;
    private final String reason;

    public Decision(boolean allow, String reason) {
        this.allow = allow;
        this.reason = reason;
    }

    public boolean allow() { return allow; }
    public String reason() { return reason; }

    @Override
    public String toString() {
        return (allow ? "ALLOW" : "DENY") + ": " + reason;
    }
}
