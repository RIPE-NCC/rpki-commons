package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateParser;

import static net.ripe.rpki.commons.validation.ValidationString.*;

public class ProvisioningCmsCertificateParser extends X509CertificateParser<ProvisioningCmsCertificate> {

    @Override
    public ProvisioningCmsCertificate getCertificate() {
        if (!isSuccess()) {
            throw new IllegalArgumentException(String.format("Provisioning CMS Certificate validation failed: %s", result.getFailuresForAllLocations()));
        }
        return new ProvisioningCmsCertificate(getX509Certificate());
    }

    @Override
    protected void doTypeSpecificValidation() {
        result.rejectIfTrue(isResourceExtensionPresent(), RESOURCE_EXT_NOT_PRESENT);
    }
}
