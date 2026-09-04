package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.security.cert.X509Certificate;
import java.util.function.Predicate;

import static net.ripe.rpki.commons.validation.ValidationString.RESOURCE_RANGE;
import static net.ripe.rpki.commons.validation.ValidationString.ROOT_INHERITS_RESOURCES;


public class X509ResourceCertificateParentChildValidator extends X509CertificateParentChildValidator<X509ResourceCertificate> implements X509ResourceCertificateValidator {

    private final IpResourceSet resources;

    public X509ResourceCertificateParentChildValidator(ValidationOptions options,
                                                       ValidationResult result,
                                                       X509ResourceCertificate parent,
                                                       X509Crl crl,
                                                       IpResourceSet resources) {
        this(options, result, parent, crl, resources, X509CertificateUtil::isRootDefault);
    }

    public X509ResourceCertificateParentChildValidator(ValidationOptions options,
                                                       ValidationResult result,
                                                       X509ResourceCertificate parent,
                                                       X509Crl crl,
                                                       IpResourceSet resources,
                                                       Predicate<X509Certificate> isRoot) {
        super(options, result, parent, crl, isRoot);
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

        if (isRoot.test(child.getCertificate())) {
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
