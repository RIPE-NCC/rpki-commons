package net.ripe.commons.certification.validation.objectvalidators;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.validation.ValidationResult;


public interface CertificateRepositoryObjectValidator<T extends CertificateRepositoryObject> {

    void validate(String location, T object);

    ValidationResult getValidationResult();
}
