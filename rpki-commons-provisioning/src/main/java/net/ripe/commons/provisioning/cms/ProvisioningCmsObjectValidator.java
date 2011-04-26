package net.ripe.commons.provisioning.cms;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlValidator;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.provisioning.x509.ProvisioningCertificateValidator;
import net.ripe.commons.provisioning.x509.ProvisioningCmsCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

public class ProvisioningCmsObjectValidator {

    private ProvisioningCmsObject cmsObject;

    private ValidationResult validationResult;

    private ProvisioningCmsCertificate cmsCertificate;

    private ProvisioningIdentityCertificate identityCertificate;

    private X509Crl crl;


    public ProvisioningCmsObjectValidator(ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate identityCertificate) {
        this.cmsObject = cmsObject;
        this.identityCertificate = identityCertificate;
    }

    public void validate(ValidationResult validationResult) {
        this.validationResult = validationResult;

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser(validationResult);
        parser.parseCms("<cms>", cmsObject.getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        cmsCertificate = new ProvisioningCmsCertificate(cmsObject.getCmsCertificate());
        crl = new X509Crl(cmsObject.getCrl());

        validateCrl();
        validateCertificateChain();
    }


    private void validateCrl() {
        X509CrlValidator crlValidator = new X509CrlValidator(validationResult, identityCertificate);
        crlValidator.validate("<crl>", crl);
    }

    private void validateCertificateChain() {
        validateCmsCertificate();
        validateIdentityCertificate();
    }

    private void validateCmsCertificate() {
        ProvisioningCertificateValidator validator = new ProvisioningCertificateValidator(validationResult, identityCertificate, crl);
        validator.validate("<cms-cert>", cmsCertificate);
    }

    private void validateIdentityCertificate() {
        ProvisioningCertificateValidator validator = new ProvisioningCertificateValidator(validationResult, identityCertificate, crl);
        validator.validate("<identity-cert>", identityCertificate);
    }
}
