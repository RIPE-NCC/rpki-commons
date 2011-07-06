package net.ripe.commons.certification.validation.objectvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;


public class X509ResourceCertificateParentChildValidator extends X509CertificateParentChildValidator <X509ResourceCertificate> implements X509ResourceCertificateValidator {

    private IpResourceSet resources;


    public X509ResourceCertificateParentChildValidator(ValidationResult result, X509ResourceCertificate parent, X509Crl crl, IpResourceSet resources) {
        super(result, parent, crl);
        this.resources = resources;
    }

    @Override
    public void validate(String location, X509ResourceCertificate certificate) {
        super.validate(location, certificate);
        verifyResources();
    }

    private void verifyResources() {
        ValidationResult result = getValidationResult();
        X509ResourceCertificate child = getChild();
        IpResourceSet childResourceSet = child.getResources();

        if (child.isRoot()) {
            // root certificate cannot have inherited resources
            result.isFalse(childResourceSet instanceof InheritedIpResourceSet, RESOURCE_RANGE);
        } else if (childResourceSet instanceof InheritedIpResourceSet) {
            // for other certs inherited resources should always be okay
            return;
        } else {
            // otherwise the child resources cannot exceed the specified resources
            result.isTrue(resources.contains(childResourceSet), RESOURCE_RANGE);
        }
    }

}
