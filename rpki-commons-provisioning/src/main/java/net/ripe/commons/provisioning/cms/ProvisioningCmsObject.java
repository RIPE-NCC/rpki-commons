package net.ripe.commons.provisioning.cms;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

public class ProvisioningCmsObject {

    private byte[] encodedContent;

    private final X509Certificate cmsCertificate;

    private final Collection<X509Certificate> caCertificates;

    private final X509CRL crl;


    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate cmsCertificate, Collection<X509Certificate> caCertificates, X509CRL crl) { //NOPMD - ArrayIsStoredDirectly
        this.encodedContent = encodedContent;
        this.cmsCertificate = cmsCertificate;
        this.caCertificates = caCertificates;
        this.crl = crl;
    }

    public byte[] getEncoded() {
        return encodedContent;
    }

    public X509Certificate getCmsCertificate() {
        return cmsCertificate;
    }

    public Collection<X509Certificate> getCaCertificates() {
        return caCertificates;
    }

    public X509CRL getCrl() {
        return crl;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encodedContent);
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
        final ProvisioningCmsObject other = (ProvisioningCmsObject) obj;
        return Arrays.equals(encodedContent, other.getEncoded());
    }
}
