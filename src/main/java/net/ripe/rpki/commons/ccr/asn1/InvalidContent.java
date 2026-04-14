package net.ripe.rpki.commons.ccr.asn1;

public class InvalidContent extends RuntimeException {
    public static InvalidContent unexpectedValue(String type, String expected, String actual) {
        return new InvalidContent("Invalid value for %s: expected %s, but was %s.".formatted(type, expected, actual));
    }

    public InvalidContent(String message) {
        super(message);
    }

    public InvalidContent(String message, Throwable cause) {
        super(message, cause);
    }
}
