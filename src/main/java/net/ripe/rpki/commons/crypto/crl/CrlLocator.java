package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import java.net.URI;


public interface CrlLocator {

    X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result);
}
