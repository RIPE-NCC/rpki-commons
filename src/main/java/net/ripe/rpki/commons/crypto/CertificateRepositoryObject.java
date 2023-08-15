package net.ripe.rpki.commons.crypto;

import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.time.Instant;

public interface CertificateRepositoryObject {

    URI getCrlUri();

    URI getParentCertificateUri();

    void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result);
    void validate(String location, CertificateRepositoryObjectValidationContext context, X509Crl crl, URI crlUri, ValidationOptions options, ValidationResult result);

    boolean isPastValidityTime(@NotNull Instant instant);

    boolean isRevoked();

    byte[] getEncoded();
}
