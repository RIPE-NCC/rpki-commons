package net.ripe.commons.certification;

public class Asn1UtilException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public Asn1UtilException(String msg, Exception e) {
        super(msg, e);
    }
}
