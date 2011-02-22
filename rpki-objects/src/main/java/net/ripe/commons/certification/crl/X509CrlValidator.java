package net.ripe.commons.certification.crl;

import java.security.SignatureException;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidator;
import net.ripe.commons.certification.x509cert.X509PlainCertificate;

import org.joda.time.DateTime;

public class X509CrlValidator implements CertificateRepositoryObjectValidator<X509Crl>{

    private X509PlainCertificate parent;

    private ValidationResult result;


    public X509CrlValidator(ValidationResult result, X509PlainCertificate parent) {
        this.result = result;
        this.parent = parent;
    }

    @Override
    public ValidationResult getValidationResult() {
        return result;
    }

    @Override
    public void validate(String location, X509Crl crl) {
        result.push(location);
        checkSignature(crl);
        checkNextUpdate(crl);
    }

    private void checkNextUpdate(X509Crl crl) {
        DateTime nextUpdateTime = crl.getNextUpdateTime();
        result.isTrue(nextUpdateTime.isAfterNow(), ValidationString.CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime);

    }

    private void checkSignature(X509Crl crl) {
        boolean signatureValid;
        try {
            crl.verify(parent.getPublicKey());
            signatureValid = true;
        } catch (SignatureException e) {
            signatureValid = false;
        }
        result.isTrue(signatureValid, ValidationString.CRL_SIGNATURE_VALID);
    }
}
