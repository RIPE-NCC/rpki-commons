package net.ripe.commons.provisioning.x509;

import java.security.cert.X509Certificate;

import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapper;

public class ProvisioningCmsCertificate extends AbstractX509CertificateWrapper {

    public ProvisioningCmsCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
