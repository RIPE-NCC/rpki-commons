package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.X509CertificateParentChildValidator;


public class ProvisioningCertificateValidator extends X509CertificateParentChildValidator<ProvisioningCertificate> {

    public ProvisioningCertificateValidator(ValidationOptions options, ValidationResult result, ProvisioningCertificate parent, X509Crl crl) {
        super(options, result, parent, crl);
    }

}
