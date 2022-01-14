package net.ripe.rpki.commons.crypto.util;

public class Asn1UtilException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public Asn1UtilException(String msg, Exception e) {
        super(msg, e);
    }
}
