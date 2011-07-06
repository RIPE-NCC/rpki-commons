package net.ripe.commons.certification.crl;

import java.net.URI;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;


public interface CrlLocator {

	X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result);
}
