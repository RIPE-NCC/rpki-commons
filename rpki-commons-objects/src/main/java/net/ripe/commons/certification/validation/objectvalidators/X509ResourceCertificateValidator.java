package net.ripe.commons.certification.validation.objectvalidators;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509PlainCertificate;

public interface X509ResourceCertificateValidator extends CertificateRepositoryObjectValidator<X509PlainCertificate>{

	@Override
    ValidationResult getValidationResult();

	@Override
    void validate(String location, X509PlainCertificate certificate);
}
