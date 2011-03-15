package net.ripe.commons.provisioning.x509;

import java.security.cert.X509Certificate;

import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapper;

public class ProvisioningIdentityCertificate extends AbstractX509CertificateWrapper {

    public ProvisioningIdentityCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
