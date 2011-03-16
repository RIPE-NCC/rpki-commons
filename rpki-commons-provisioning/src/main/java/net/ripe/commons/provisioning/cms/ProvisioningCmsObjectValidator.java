package net.ripe.commons.provisioning.cms;

import java.security.cert.X509Certificate;
import java.util.Collection;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlValidator;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.provisioning.x509.ProvisioningCmsCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

import org.apache.commons.lang.Validate;

public class ProvisioningCmsObjectValidator {

    private ProvisioningCmsObject cmsObject;

    private String location = "<change-me>"; //TODO: sort out the locations

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
        parser.parseCms(location, cmsObject.getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        ProvisioningCmsObject provisioningCmsObject = parser.getProvisioningCmsObject();
        cmsCertificate = new ProvisioningCmsCertificate(provisioningCmsObject.getCmsCertificate());

        Collection<X509Certificate> caCertificates = provisioningCmsObject.getCaCertificates();
        Validate.isTrue(!caCertificates.isEmpty(), "identity certificate is required");
        Validate.isTrue(caCertificates.size() == 1, "multiple embedded ca certificates is not supported");
        identityCertificate = new ProvisioningIdentityCertificate(caCertificates.iterator().next());

        crl = new X509Crl(provisioningCmsObject.getCrl());


        validateCrl();
        //TODO: the identity certificate should be compared to the one which has been uploaded to the 'up'.
        // If they are the same (and that one was validated at the time of uploading) we don't have to validate
        // here therefore I am not validating the identity certificate

        //TODO: validate chain which is validating the cms cert with its parent (the identity cert)
        //validationResult.isFalse(crl.isRevoked(cmsCertificate), CERT_NOT_REVOKED);
    }


    private void validateCrl() {
        X509CrlValidator crlValidator = new X509CrlValidator(validationResult, identityCertificate);
        crlValidator.validate(location, crl);
    }
}
