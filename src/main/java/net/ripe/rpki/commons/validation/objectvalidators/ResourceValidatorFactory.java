package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.security.cert.X509Certificate;
import java.util.function.Predicate;

public class ResourceValidatorFactory {

    public static X509ResourceCertificateParentChildValidator getX509ResourceCertificateStrictValidator(
            CertificateRepositoryObjectValidationContext context,
            ValidationOptions options, ValidationResult result, X509Crl crl) {
        return getX509ResourceCertificateStrictValidator(context, options, result, crl, X509CertificateUtil::isRootDefault);
    }

    public static X509ResourceCertificateParentChildValidator getX509ResourceCertificateStrictValidator(
            CertificateRepositoryObjectValidationContext context,
            ValidationOptions options, ValidationResult result, X509Crl crl,
            Predicate<X509Certificate> isRoot) {
        return new X509ResourceCertificateParentChildValidator(options, result, context.getCertificate(), crl, context.getResources(), isRoot);
    }

    public static X509ResourceCertificateValidator getX509ResourceCertificateValidator(
            CertificateRepositoryObjectValidationContext context,
            ValidationOptions options, ValidationResult result, X509Crl crl) {
        return getX509ResourceCertificateValidator(context, options, result, crl, X509CertificateUtil::isRootDefault);
    }

    public static X509ResourceCertificateValidator getX509ResourceCertificateValidator(
            CertificateRepositoryObjectValidationContext context,
            ValidationOptions options, ValidationResult result, X509Crl crl,
            Predicate<X509Certificate> isRoot) {
        if (options.isAllowOverclaimParentChild())
            return new X509ResourceCertificateParentChildLooseValidator(options, result, crl, context, isRoot);

        return new X509ResourceCertificateParentChildValidator(options, result, context.getCertificate(), crl, context.getResources(), isRoot);
    }

    public static X509ResourceCertificateParentChildValidator getX509ResourceCertificateParentChildStrictValidator(
            ValidationOptions options, ValidationResult result, X509ResourceCertificate parent,
            IpResourceSet resources, X509Crl crl) {
        return getX509ResourceCertificateParentChildStrictValidator(options, result, parent, resources, crl, X509CertificateUtil::isRootDefault);
    }

    public static X509ResourceCertificateParentChildValidator getX509ResourceCertificateParentChildStrictValidator(
            ValidationOptions options, ValidationResult result, X509ResourceCertificate parent,
            IpResourceSet resources, X509Crl crl, Predicate<X509Certificate> isRoot) {
        return new X509ResourceCertificateParentChildValidator(options, result, parent, crl, resources, isRoot);
    }
}
