package com.agentguard;

/** Thrown when a token is malformed, expired, or fails verification. */
public class TokenException extends Exception {
    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
