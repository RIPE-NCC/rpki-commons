package net.ripe.rpki.commons.provisioning.identity;

public class IdentitySerializerException extends Exception {
    public IdentitySerializerException(Exception e) {
        super(e);
    }

    public IdentitySerializerException(final String message) {
        super(message);
    }

    public IdentitySerializerException(final String message, final Exception e) {
        super(message, e);
    }
}
