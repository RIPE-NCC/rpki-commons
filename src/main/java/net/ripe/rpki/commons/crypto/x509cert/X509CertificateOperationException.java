package net.ripe.rpki.commons.crypto.x509cert;

/**
 * RuntimeException for any checked exceptions related to X509Certificate operations
 * that we have no better way of dealing with.
 */
public class X509CertificateOperationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public X509CertificateOperationException(Exception e) {
        super(e);
    }

    public X509CertificateOperationException(String msg, Exception e) {
        super(msg, e);
    }
}
