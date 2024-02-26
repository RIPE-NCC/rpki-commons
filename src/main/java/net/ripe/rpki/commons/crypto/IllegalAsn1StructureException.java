package net.ripe.rpki.commons.crypto;

/**
 * Encountered an ASN.1 structure that was not expected (e.g. implicit instead of explicit tags).
 */
public class IllegalAsn1StructureException extends IllegalArgumentException {
    public IllegalAsn1StructureException(String message) {
        super(message);
    }

    public IllegalAsn1StructureException(String message, Throwable cause) {
        super(message, cause);
    }
}
