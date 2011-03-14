package net.ripe.commons.certification.x509cert;

import net.ripe.commons.certification.validation.ValidationResult;


public class X509ResourceCertificateParser extends X509CertificateParser<X509ResourceCertificate> {

    public X509ResourceCertificateParser() {
        this(new ValidationResult());
    }

    public X509ResourceCertificateParser(ValidationResult result) {
        super(X509ResourceCertificate.class, result);
    }

    @Override
    public X509ResourceCertificate getCertificate() {
        if (getValidationResult().hasFailures()) {
            throw new IllegalArgumentException("Certificate validation failed");
        }
        return new X509ResourceCertificate(getX509Certificate());
    }
}
