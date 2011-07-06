package net.ripe.commons.certification;

import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateValidator;

import java.io.Serializable;
import java.net.URI;

public interface CertificateRepositoryObject extends Serializable {

    void validate(String location, X509ResourceCertificateValidator validator);

    URI getCrlUri();

    URI getParentCertificateUri();

    void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationResult result);

    byte[] getEncoded();
}
