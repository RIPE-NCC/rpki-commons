package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.ImmutableResourceSet;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

public class ResourceValidatorFactory {

    public static X509ResourceCertificateParentChildValidator getX509ResourceCertificateStrictValidator(
            CertificateRepositoryObjectValidationContext context,
            ValidationOptions options, ValidationResult result, X509Crl crl) {

        return new X509ResourceCertificateParentChildValidator(options, result, context.getCertificate(), crl, ImmutableResourceSet.of(context.getResources()));
    }

    public static X509ResourceCertificateValidator getX509ResourceCertificateValidator(
            CertificateRepositoryObjectValidationContext context,
            ValidationOptions options, ValidationResult result, X509Crl crl) {

        if (options.isAllowOverclaimParentChild())
            return new X509ResourceCertificateParentChildLooseValidator(options, result, crl, context);

        return new X509ResourceCertificateParentChildValidator(options, result, context.getCertificate(), crl, ImmutableResourceSet.of(context.getResources()));
    }

    public static X509ResourceCertificateParentChildValidator getX509ResourceCertificateParentChildStrictValidator(
            ValidationOptions options, ValidationResult result, X509ResourceCertificate parent,
            ImmutableResourceSet resources, X509Crl crl) {
        return new X509ResourceCertificateParentChildValidator(options, result, parent, crl, resources);
    }
}
