package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.validation.ValidationResult;


public interface CertificateRepositoryObjectValidator<T extends CertificateRepositoryObject> {

    void validate(String location, T object);

    ValidationResult getValidationResult();
}
