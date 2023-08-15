package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidator;

import java.security.SignatureException;

public class X509CrlValidator implements CertificateRepositoryObjectValidator<X509Crl> {

    private final AbstractX509CertificateWrapper parent;

    private final ValidationOptions options;
    private final ValidationResult result;


    public X509CrlValidator(ValidationOptions options, ValidationResult result, AbstractX509CertificateWrapper parent) {
        this.options = options;
        this.result = result;
        this.parent = parent;
    }

    @Override
    public ValidationResult getValidationResult() {
        return result;
    }

    @Override
    public void validate(String location, X509Crl crl) {
        result.setLocation(new ValidationLocation(location));
        checkSignature(crl);
        checkValidityTimes(crl);
    }

    private void checkValidityTimes(X509Crl crl) {
        var now = result.now();
        var nextUpdateTime = crl.getNextUpdateTime();
        var thisUpdateTime = crl.getThisUpdateTime();

        result.rejectIfTrue(thisUpdateTime.isAfter(now), ValidationString.CRL_THIS_UPDATE_AFTER_NOW, thisUpdateTime.toString());
        if (options.isStrictManifestCRLValidityChecks()) {
            boolean postGracePeriod = now.isAfter(nextUpdateTime.plus(options.getCrlMaxStalePeriod()));
            if (postGracePeriod) {
                result.error(ValidationString.CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime.toString());
            } else {
                result.warnIfTrue(now.isAfter(nextUpdateTime), ValidationString.CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime.toString());
            }
        } else {
            result.warnIfTrue(now.isAfter(nextUpdateTime), ValidationString.CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime.toString());
        }
    }

    private void checkSignature(X509Crl crl) {
        boolean signatureValid;
        try {
            crl.verify(parent.getPublicKey());
            signatureValid = true;
        } catch (SignatureException e) {
            signatureValid = false;
        }
        result.rejectIfFalse(signatureValid, ValidationString.CRL_SIGNATURE_VALID);
    }
}
