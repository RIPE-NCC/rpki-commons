package net.ripe.commons.provisioning.x509;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509CertificateParser;

public class ProvisioningCmsCertificateParser extends X509CertificateParser<ProvisioningCmsCertificate> {

    public ProvisioningCmsCertificateParser() {
        this(new ValidationResult());
    }

    public ProvisioningCmsCertificateParser(ValidationResult result) {
        super(ProvisioningCmsCertificate.class, result);
    }

    @Override
    public ProvisioningCmsCertificate getCertificate() {
        if (getValidationResult().hasFailures()) {
            throw new IllegalArgumentException("Provisioning CMS Certificate validation failed");
        }
        return new ProvisioningCmsCertificate(getX509Certificate());
    }
}
