package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateParser;

import static net.ripe.rpki.commons.validation.ValidationString.*;

public class ProvisioningIdentityCertificateParser extends X509CertificateParser<ProvisioningIdentityCertificate> {

    @Override
    public ProvisioningIdentityCertificate getCertificate() {
        if (!isSuccess()) {
            throw new IllegalArgumentException(String.format("Identity Certificate validation failed: %s", result.getFailuresForAllLocations()));
        }
        return new ProvisioningIdentityCertificate(getX509Certificate());
    }

    @Override
    protected void doTypeSpecificValidation() {
        result.rejectIfTrue(isResourceExtensionPresent(), RESOURCE_EXT_NOT_PRESENT);
    }
}
