package net.ripe.commons.provisioning.x509;

import java.security.cert.X509Certificate;

public class ProvisioningIdentityCertificate extends ProvisioningCertificate {

    public ProvisioningIdentityCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
