package net.ripe.commons.provisioning.x509;

import java.security.cert.X509Certificate;

import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapper;

public class ProvisioningCertificate extends AbstractX509CertificateWrapper {

    private static final long serialVersionUID = 1L;

    public ProvisioningCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
