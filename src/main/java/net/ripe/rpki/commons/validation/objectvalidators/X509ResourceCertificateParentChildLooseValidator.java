package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import static net.ripe.rpki.commons.validation.ValidationString.RESOURCE_RANGE;
import static net.ripe.rpki.commons.validation.ValidationString.ROOT_INHERITS_RESOURCES;


public class X509ResourceCertificateParentChildLooseValidator extends X509CertificateParentChildValidator<X509ResourceCertificate> implements X509ResourceCertificateValidator {

    private final CertificateRepositoryObjectValidationContext context;

    public X509ResourceCertificateParentChildLooseValidator(ValidationOptions options,
                                                            ValidationResult result,
                                                            X509Crl crl,
                                                            CertificateRepositoryObjectValidationContext context) {
        super(options, result, context.getCertificate(), crl);
        this.context = context;
    }

    @Override
    public void validate(String location, X509ResourceCertificate certificate) {
        super.validate(location, certificate);
        verifyResources();
    }

    private void verifyResources() {
        final ValidationResult result = getValidationResult();
        final X509ResourceCertificate child = getChild();
        final IpResourceSet resources = context.getResources();
        final IpResourceSet childResourceSet = child.deriveResources(resources);

        if (child.isRoot()) {
            result.rejectIfTrue(child.isResourceSetInherited(), ROOT_INHERITS_RESOURCES);
        } else {
            if (!resources.contains(childResourceSet)) {
                IpResourceSet overclaiming = new IpResourceSet(childResourceSet);
                overclaiming.removeAll(resources);

                context.addOverclaiming(overclaiming);
                result.warnIfFalse(overclaiming.isEmpty(), RESOURCE_RANGE, overclaiming.toString());
            }
        }
    }

}
