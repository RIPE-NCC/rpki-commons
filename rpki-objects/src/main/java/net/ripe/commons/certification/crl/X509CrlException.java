package net.ripe.commons.certification.crl;


/**
 * RuntimeException to wrap checked Exceptions. In general we have no
 * way to recover from any of the checked Exceptions related to X509CRLs
 * so we might as well throw a RuntimeException..
 */
public class X509CrlException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public X509CrlException(String msg, Exception e) {
        super(msg, e);
    }

}
