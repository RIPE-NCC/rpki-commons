package net.ripe.commons.certification.validation.objectvalidators;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

public interface X509ResourceCertificateValidator extends CertificateRepositoryObjectValidator<X509ResourceCertificate>{

	@Override
    ValidationResult getValidationResult();

	@Override
    void validate(String location, X509ResourceCertificate certificate);
}
