package net.ripe.commons.provisioning.cms;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

public class ProvisioningCmsObject {

    private byte[] encodedContent;

    private X509Certificate cmsCertificate;

    private final Collection<X509Certificate> caCertificates;


    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate cmsCertificate, Collection<X509Certificate> caCertificates) { //NOPMD - ArrayIsStoredDirectly
        this.encodedContent = encodedContent;
        this.cmsCertificate = cmsCertificate;
        this.caCertificates = caCertificates;
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
