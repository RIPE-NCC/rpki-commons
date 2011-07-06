package net.ripe.commons.provisioning.x509;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509CertificateParser;

public class ProvisioningIdentityCertificateParser extends X509CertificateParser<ProvisioningIdentityCertificate> {

    public ProvisioningIdentityCertificateParser() {
        this(new ValidationResult());
    }

    public ProvisioningIdentityCertificateParser(ValidationResult result) {
        super(ProvisioningIdentityCertificate.class, result);
    }

    @Override
    public ProvisioningIdentityCertificate getCertificate() {
        if (getValidationResult().hasFailures()) {
            throw new IllegalArgumentException("Identity Certificate validation failed");
        }
        return new ProvisioningIdentityCertificate(getX509Certificate());
    }
}
