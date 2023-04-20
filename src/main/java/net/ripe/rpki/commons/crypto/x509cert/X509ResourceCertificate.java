package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.ImmutableResourceSet;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtension;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionParser;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateValidator;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.EnumSet;

/**
 * Wraps a X509 certificate containing RFC3779 resource extensions.
 */
public class X509ResourceCertificate extends X509GenericCertificate implements X509CertificateObject {

    private static final long serialVersionUID = 3L;

    private final ResourceExtension resourceExtension;
    private Boolean revoked;


    protected X509ResourceCertificate(X509Certificate certificate) {
        super(certificate);
        ResourceExtensionParser parser = new ResourceExtensionParser();
        resourceExtension = parser.parse(certificate);
    }

    public ResourceExtension getResourceExtension() {
        return resourceExtension;
    }

    public ImmutableResourceSet resources() {
        return resourceExtension.getResources();
    }

    public IpResourceSet getResources() {
        return new IpResourceSet(resources());
    }

    public EnumSet<IpResourceType> getInheritedResourceTypes() {
        return EnumSet.copyOf(resourceExtension.getInheritedResourceTypes());
    }

    public boolean isResourceTypesInherited(EnumSet<IpResourceType> resourceTypes) {
        return resourceExtension.isResourceTypesInherited(resourceTypes);
    }

    public boolean isResourceSetInherited() {
        return resourceExtension.isResourceSetInherited();
    }

    @Override
    public URI getCrlUri() {
        return findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public URI getParentCertificateUri() {
        return findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS);
    }

    public void validate(String location, X509ResourceCertificateValidator validator) {
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse(ValidationResult.withLocation(location), getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        validator.validate(location, this);
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        X509Crl crl = null;
        if (!isRoot()) {
            ValidationLocation savedCurrentLocation = result.getCurrentLocation();
            result.setLocation(new ValidationLocation(getCrlUri()));
            crl = crlLocator.getCrl(getCrlUri(), context, result);
            result.setLocation(savedCurrentLocation);
            if (crl == null) {
                result.rejectIfFalse(false, ValidationString.OBJECTS_CRL_VALID, getCrlUri().toString());
                return;
            }
        }
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateValidator(context, options, result, crl);
        validator.validate(location, this);

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));
    }

    @Override
    public void validate(String location,
                         CertificateRepositoryObjectValidationContext context,
                         X509Crl crl,
                         URI crlUri,
                         ValidationOptions options,
                         ValidationResult result) {
        if (!isRoot() && crl == null) {
            result.rejectIfFalse(false, ValidationString.OBJECTS_CRL_VALID, crlUri.toString());
            return;
        }
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateValidator(context, options, result, crl);
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

    public IpResourceSet deriveResources(IpResourceSet parentResources) {
        return new IpResourceSet(resourceExtension.deriveResources(ImmutableResourceSet.of(parentResources)));
    }

    public boolean containsResources(IpResourceSet that) {
        return resourceExtension.containsResources(that);
    }
}
