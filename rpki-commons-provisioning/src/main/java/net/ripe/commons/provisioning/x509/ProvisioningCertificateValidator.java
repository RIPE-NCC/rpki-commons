package net.ripe.commons.provisioning.x509;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.X509CertificateParentChildValidator;


public class ProvisioningCertificateValidator extends X509CertificateParentChildValidator <ProvisioningCertificate> {

    public ProvisioningCertificateValidator(ValidationResult result, ProvisioningCertificate parent, X509Crl crl) {
        super(result, parent, crl);
    }
}
