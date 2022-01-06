package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlValidator;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCertificateValidator;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

public class ProvisioningCmsObjectValidator {

    private ValidationOptions options;
    private ProvisioningCmsObject cmsObject;
    private ProvisioningIdentityCertificate identityCertificate;

    private ValidationResult validationResult;
    private ProvisioningCmsCertificate cmsCertificate;

    private X509Crl crl;

    public ProvisioningCmsObjectValidator(ValidationOptions options, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate identityCertificate) {
        this.options = options;
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
        X509CrlValidator crlValidator = new X509CrlValidator(options, validationResult, identityCertificate);
        crlValidator.validate("<crl>", crl);
    }

    private void validateCertificateChain() {
        validateCmsCertificate();
        validateIdentityCertificate();
    }

    private void validateCmsCertificate() {
        ProvisioningCertificateValidator validator = new ProvisioningCertificateValidator(options, validationResult, identityCertificate, crl);
        validator.validate("<cms-cert>", cmsCertificate);
    }

    private void validateIdentityCertificate() {
        ProvisioningCertificateValidator validator = new ProvisioningCertificateValidator(options, validationResult, identityCertificate, crl);
        validator.validate("<identity-cert>", identityCertificate);
    }
}
