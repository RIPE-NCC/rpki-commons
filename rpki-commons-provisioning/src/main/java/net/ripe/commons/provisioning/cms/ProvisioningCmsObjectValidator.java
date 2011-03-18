package net.ripe.commons.provisioning.cms;

import java.security.cert.X509Certificate;
import java.util.Collection;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlValidator;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.provisioning.x509.ProvisioningCertificateValidator;
import net.ripe.commons.provisioning.x509.ProvisioningCmsCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

import org.apache.commons.lang.Validate;

public class ProvisioningCmsObjectValidator {

    private ProvisioningCmsObject cmsObject;

    private ValidationResult validationResult;

    private ProvisioningCmsCertificate cmsCertificate;

    private ProvisioningIdentityCertificate identityCertificate;

    private X509Crl crl;


    public ProvisioningCmsObjectValidator(ProvisioningCmsObject cmsObject) {
        this.cmsObject = cmsObject;
    }

    public void validate(ValidationResult validationResult) {
        this.validationResult = validationResult;

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser(validationResult);
        parser.parseCms("<cms>", cmsObject.getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        ProvisioningCmsObject provisioningCmsObject = parser.getProvisioningCmsObject();
        cmsCertificate = new ProvisioningCmsCertificate(provisioningCmsObject.getCmsCertificate());

        Collection<X509Certificate> caCertificates = provisioningCmsObject.getCaCertificates();
        Validate.isTrue(!caCertificates.isEmpty(), "identity certificate is required");
        Validate.isTrue(caCertificates.size() == 1, "multiple embedded ca certificates is not supported");

        //TODO: the identity certificate should be compared to the one which has been uploaded to the 'up'.
        // If they are the same (and that one was parsed at the time of uploading) we don't have to parse it
        // here therefore I am not parsing the identity certificate, only validating it to check validity time, etc.
        identityCertificate = new ProvisioningIdentityCertificate(caCertificates.iterator().next());

        crl = new X509Crl(provisioningCmsObject.getCrl());


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
