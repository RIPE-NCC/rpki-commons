package net.ripe.commons.provisioning.cms;

import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ProvisioningCmsObject {

    private byte[] encodedContent;

    private X509Certificate certificate;


    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate certificate) { //NOPMD - ArrayIsStoredDirectly
        this.encodedContent = encodedContent;
        this.certificate = certificate;
    }

    public byte[] getEncoded() {
        return encodedContent;
    }

    public X509Certificate getCertificate() {
        return certificate;
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
