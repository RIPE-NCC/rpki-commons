package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.security.cert.X509Certificate;
import java.util.function.Predicate;

public class X509RouterCertificateValidator extends X509CertificateParentChildValidator<X509RouterCertificate> implements CertificateRepositoryObjectValidator<X509RouterCertificate> {

    public X509RouterCertificateValidator(ValidationOptions options, ValidationResult result, X509RouterCertificate parent, X509Crl crl) {
        this(options, result, parent, crl, X509CertificateUtil::isRootDefault);
    }

    public X509RouterCertificateValidator(ValidationOptions options, ValidationResult result, X509RouterCertificate parent, X509Crl crl, Predicate<X509Certificate> isRoot) {
        super(options, result, parent, crl, isRoot);
    }

}
