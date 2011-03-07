package net.ripe.commons.certification.x509cert;

/**
 * RuntimeException for any checked exceptions related to X509Certificates
 * that we have no better way of dealing with. 
 */
public class X509PlainCertificateException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public X509PlainCertificateException(Exception e) {
        super(e);
    }

    public X509PlainCertificateException(String msg, Exception e) {
        super(msg, e);
    }
}
