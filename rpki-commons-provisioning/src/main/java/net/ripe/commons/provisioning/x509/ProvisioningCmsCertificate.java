package net.ripe.commons.provisioning.x509;

import java.security.cert.X509Certificate;

public class ProvisioningCmsCertificate extends ProvisioningCertificate {

    private static final long serialVersionUID = 1L;

    public ProvisioningCmsCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
