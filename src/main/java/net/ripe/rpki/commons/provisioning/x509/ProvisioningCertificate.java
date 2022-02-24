package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper;

import java.security.cert.X509Certificate;

/**
 * A provisioning certificate.
 *
 * This could be a RFC6492 EE certificate, but can also be a (self-signed) identity certificate.
 */
public class ProvisioningCertificate extends AbstractX509CertificateWrapper {

    private static final long serialVersionUID = 1L;

    public ProvisioningCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
