package net.ripe.commons.certification.x509cert;

/**
 * RuntimeException for any checked exceptions related to X509Certificate wrappers
 * that we have no better way of dealing with. 
 */
public class AbstractX509CertificateWrapperException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AbstractX509CertificateWrapperException(Exception e) {
        super(e);
    }

    public AbstractX509CertificateWrapperException(String msg, Exception e) {
        super(msg, e);
    }
}
