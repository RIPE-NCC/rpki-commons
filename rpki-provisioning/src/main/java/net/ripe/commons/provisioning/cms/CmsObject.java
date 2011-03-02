package net.ripe.commons.provisioning.cms;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.cms.CMSSignedDataGenerator;

public class CmsObject {

    public static final int VERSION = 3;

    public static final String DIGEST_ALGORITHM_OID = CMSSignedDataGenerator.DIGEST_SHA256;

    public static final String CONTENT_TYPE = "1.2.840.113549.1.9.16.1.28";

    private byte[] encodedContent;

    private X509Certificate certificate;


    public CmsObject(byte[] encodedContent, X509Certificate certificate) {
        super();
        this.encodedContent = encodedContent;
        this.certificate = certificate;
    }

    public byte[] getEncodedContent() {
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
        final CmsObject other = (CmsObject) obj;
        return Arrays.equals(encodedContent, other.getEncodedContent());
    }
}
