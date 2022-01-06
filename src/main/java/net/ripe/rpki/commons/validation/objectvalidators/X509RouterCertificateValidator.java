package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

public class X509RouterCertificateValidator extends X509CertificateParentChildValidator<X509RouterCertificate> implements CertificateRepositoryObjectValidator<X509RouterCertificate> {

    public X509RouterCertificateValidator(ValidationOptions options, ValidationResult result, X509RouterCertificate parent, X509Crl crl) {
        super(options, result, parent, crl);
    }

}
