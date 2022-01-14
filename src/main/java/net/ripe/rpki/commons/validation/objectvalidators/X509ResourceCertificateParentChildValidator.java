package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import static net.ripe.rpki.commons.validation.ValidationString.*;


public class X509ResourceCertificateParentChildValidator extends X509CertificateParentChildValidator<X509ResourceCertificate> implements X509ResourceCertificateValidator {

    private IpResourceSet resources;

    public X509ResourceCertificateParentChildValidator(ValidationOptions options,
                                                       ValidationResult result,
                                                       X509ResourceCertificate parent,
                                                       X509Crl crl,
                                                       IpResourceSet resources) {
        super(options, result, parent, crl);
        this.resources = resources;
    }

    @Override
    public void validate(String location, X509ResourceCertificate certificate) {
        super.validate(location, certificate);
        verifyResources();
    }

    private void verifyResources() {
        final ValidationResult result = getValidationResult();
        final X509ResourceCertificate child = getChild();
        final IpResourceSet childResourceSet = child.deriveResources(resources);

        if (child.isRoot()) {
            result.rejectIfTrue(child.isResourceSetInherited(), ROOT_INHERITS_RESOURCES);
        } else {
            if (!resources.contains(childResourceSet)) {
                final IpResourceSet overclaiming = new IpResourceSet(childResourceSet);
                overclaiming.removeAll(resources);
                result.rejectIfFalse(overclaiming.isEmpty(), RESOURCE_RANGE, overclaiming.toString());
            }
        }
    }

}
