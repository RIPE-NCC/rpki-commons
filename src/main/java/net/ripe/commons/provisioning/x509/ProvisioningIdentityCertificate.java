package net.ripe.commons.provisioning.x509;

import java.io.Serializable;
import java.security.cert.X509Certificate;

public class ProvisioningIdentityCertificate extends ProvisioningCertificate implements Serializable {

    private static final long serialVersionUID = 1L;
    
    public ProvisioningIdentityCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
