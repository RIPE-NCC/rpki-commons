package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.X509CertificateParentChildValidator;

import java.security.cert.X509Certificate;
import java.util.function.Predicate;


public class ProvisioningCertificateValidator extends X509CertificateParentChildValidator<ProvisioningCertificate> {

    public ProvisioningCertificateValidator(ValidationOptions options, ValidationResult result, ProvisioningCertificate parent, X509Crl crl) {
        this(options, result, parent, crl, X509CertificateUtil::isRootDefault);
    }

    public ProvisioningCertificateValidator(ValidationOptions options, ValidationResult result, ProvisioningCertificate parent, X509Crl crl, Predicate<X509Certificate> isRoot) {
        super(options, result, parent, crl, isRoot);
    }

}
