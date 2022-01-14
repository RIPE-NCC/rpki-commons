package net.ripe.rpki.commons.crypto.util;

public class KeyStoreException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyStoreException(Throwable cause) {
        super(cause);
    }

    public KeyStoreException(String message) {
        super(message);
    }
}
