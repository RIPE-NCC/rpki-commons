package net.ripe.commons.provisioning.x509.pkcs10;

public class RpkiCaCertificateRequestParserException extends Exception {

    private static final long serialVersionUID = 1L;
    
    public RpkiCaCertificateRequestParserException(Exception e) {
        super(e);
    }

    public RpkiCaCertificateRequestParserException(String msg) {
        super(msg);
    }

    public RpkiCaCertificateRequestParserException(String msg, Exception e) {
        super(msg, e);
    }

}
