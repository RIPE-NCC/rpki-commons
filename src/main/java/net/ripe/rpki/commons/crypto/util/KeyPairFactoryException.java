package net.ripe.rpki.commons.crypto.util;

public class KeyPairFactoryException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyPairFactoryException(Exception e) {
        super(e);
    }

    public KeyPairFactoryException(String msg) {
        super(msg);
    }
}
