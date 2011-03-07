package net.ripe.commons.provisioning.x509;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.Validate;

public class ProvisioningIdentityCertificate implements Serializable {

    private static final long serialVersionUID = 1L;

    private X509Certificate certificate;

    ProvisioningIdentityCertificate(X509Certificate certificate) {
        Validate.notNull(certificate);
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public int hashCode() {
        return certificate.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ProvisioningIdentityCertificate other = (ProvisioningIdentityCertificate) obj;
        return certificate.equals(other.certificate);
    }
}
