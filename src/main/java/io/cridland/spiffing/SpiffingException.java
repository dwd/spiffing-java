package io.cridland.spiffing;

/**
 * Invalid input, unresolved policy references, or policy constraint violations.
 */
public class SpiffingException extends IllegalArgumentException {
    public SpiffingException(String message) {
        super(message);
    }

    public SpiffingException(String message, Throwable cause) {
        super(message, cause);
    }
}
