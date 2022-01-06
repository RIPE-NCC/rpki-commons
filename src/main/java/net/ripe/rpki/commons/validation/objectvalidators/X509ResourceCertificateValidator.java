package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;

public interface X509ResourceCertificateValidator extends CertificateRepositoryObjectValidator<X509ResourceCertificate> {

    @Override
    ValidationResult getValidationResult();

    @Override
    void validate(String location, X509ResourceCertificate certificate);
}
