package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.X509RouterCertificateValidator;

import java.net.URI;
import java.security.cert.X509Certificate;

public class X509RouterCertificate extends X509ResourceCertificate implements X509CertificateObject {

    protected X509RouterCertificate(X509Certificate certificate) {
        super(certificate);
    }

    @Override
    public URI getCrlUri() {
        return findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public URI getParentCertificateUri() {
        return findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS);
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        final ValidationLocation savedCurrentLocation = result.getCurrentLocation();
        result.setLocation(new ValidationLocation(getCrlUri()));
        result.setLocation(savedCurrentLocation);

        final X509Crl crl = crlLocator.getCrl(getCrlUri(), context, result);
        if (crl == null) {
            result.rejectIfFalse(false, ValidationString.OBJECTS_CRL_VALID, getCrlUri().toString());
            return;
        }

        X509RouterCertificateValidator validator = new X509RouterCertificateValidator(options, result, context.getRouterCertificate(), crl);
        validator.validate(location, this);

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, X509Crl crl, URI crlUri, ValidationOptions options, ValidationResult result) {
        if (!isRoot() && crl == null) {
            result.rejectIfFalse(false, ValidationString.OBJECTS_CRL_VALID, crlUri.toString());
            return;
        }

        X509RouterCertificateValidator validator = new X509RouterCertificateValidator(options, result, context.getRouterCertificate(), crl);
        validator.validate(location, this);

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));
    }

    @Override
    public boolean isPastValidityTime() {
        return getValidityPeriod().isExpiredNow();
    }

    @Override
    public boolean isRevoked() {
        if (revoked == null) {
            throw new IllegalStateException("isRevoked() could only be called after validate()");
        }
        return revoked;
    }
}
