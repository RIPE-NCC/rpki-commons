package net.ripe.rpki.commons.provisioning.x509.pkcs10;

public class RpkiCaCertificateRequestBuilderException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RpkiCaCertificateRequestBuilderException(Exception e) {
        super(e);
    }
}
