package net.ripe.rpki.commons.crypto;

import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import java.net.URI;

import static net.ripe.rpki.commons.validation.ValidationString.VALIDATOR_REPO_EXECUTION;

public class UnknownCertificateRepositoryObject implements CertificateRepositoryObject {

    private static final long serialVersionUID = 1L;

    private final byte[] encoded;

    public UnknownCertificateRepositoryObject(byte[] encoded) {
        this.encoded = encoded;
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        result.warn(VALIDATOR_REPO_EXECUTION, "This object type is not supported for " + location);
    }

    @Override
    public void validate(String location,
                         CertificateRepositoryObjectValidationContext context,
                         X509Crl crl,
                         URI crlUri,
                         ValidationOptions options,
                         ValidationResult result) {
        result.warn(VALIDATOR_REPO_EXECUTION, "This object type is not supported for " + location);
    }

    @Override
    public boolean isPastValidityTime() {
        throw new UnsupportedOperationException("Unknown object type");
    }

    @Override
    public boolean isRevoked() {
        return false;
    }

    @Override
    public URI getCrlUri() {
        throw new UnsupportedOperationException("Unknown object type");
    }

    @Override
    public URI getParentCertificateUri() {
        throw new UnsupportedOperationException("Unknown object type");
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }
}
