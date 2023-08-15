package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlValidator;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCertificateValidator;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.time.Instant;
import java.util.Optional;

import static net.ripe.rpki.commons.validation.ValidationString.SIGNING_TIME_GREATER_OR_EQUAL;

/**
 *  Validating implies the checks for https://datatracker.ietf.org/doc/html/rfc6492#section-3.2
 *         5.  Validate the CMS-provided certificate using the PKI that has been
 *         determined by prior arrangement between the client and server
 *                 (see test 3 of Section 3.1.2).
 *
 * This includes validating the two provisioning cms objects in isolation, followed
 * by the validation steps that consider the identity certificate, CMS object, and
 * the signing time of previous messages.
 */
public class ProvisioningCmsObjectValidator {

    private final ValidationOptions options;
    private final ProvisioningCmsObject cmsObject;
    private final ProvisioningIdentityCertificate identityCertificate;

    private ValidationResult validationResult;
    private ProvisioningCmsCertificate cmsCertificate;

    private X509Crl crl;

    /**
     * The signing-time from the last message - if we have a previous message.
     *
     * rfc6492#3.1.1.6.4.3 requires that either one of the signing-time attribute or the binary-signing-time
     * attribute, or both attributes, MUST be present.
     */
    private final Optional<Instant> optionalLastSigningTime;

    // Prefer the constructor that moves the singning time check into this validator.
    @Deprecated
    public ProvisioningCmsObjectValidator(ValidationOptions options, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate identityCertificate) {
        this.options = options;
        this.cmsObject = cmsObject;
        this.identityCertificate = identityCertificate;
        this.optionalLastSigningTime = Optional.empty();
    }

    public ProvisioningCmsObjectValidator(ValidationOptions options, Optional<Instant> lastSigningTime, ProvisioningCmsObject cmsObject,ProvisioningIdentityCertificate identityCertificate) {
        this.options = options;
        this.cmsObject = cmsObject;
        this.identityCertificate = identityCertificate;
        this.optionalLastSigningTime = lastSigningTime;
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
        validateSigningTime();
    }

    private void validateCrl() {
        X509CrlValidator crlValidator = new X509CrlValidator(options, validationResult, identityCertificate);
        crlValidator.validate("<crl>", crl);
    }

    private void validateCertificateChain() {
        validateCmsCertificate();
        validateIdentityCertificate();
    }

    private void validateSigningTime() {
        // rfc6492#3.1.2
        // 5.  The time represented by the signing-time attribute or the binary-
        //     signing-time attribute is greater than or equal to the time value
        //     passed in previously valid CMS objects that were passed from the
        //     same originator to this recipient. [...]
        final var thisSigningTime = cmsObject.getSigningTime();

        if (thisSigningTime != null) {
            optionalLastSigningTime.ifPresent(lastSigningTime ->
                validationResult.rejectIfTrue(lastSigningTime.isAfter(thisSigningTime), SIGNING_TIME_GREATER_OR_EQUAL, lastSigningTime.toString(), thisSigningTime.toString())
            );
        }
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
