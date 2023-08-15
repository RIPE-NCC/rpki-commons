package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;

/**
 * Helper class for the creation or ResourceCertificate using CMS objects.
 */
public class RpkiSignedObjectInfo {

    private final byte[] encoded;
    private final X509ResourceCertificate resourceCertificate;
    private final ASN1ObjectIdentifier contentType;
    private final @Nullable Instant signingTime;

    public RpkiSignedObjectInfo(byte[] encoded, X509ResourceCertificate resourceCertificate, ASN1ObjectIdentifier oid, @Nullable Instant signingTime) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;
        this.resourceCertificate = resourceCertificate;
        this.contentType = oid;
        this.signingTime = signingTime;
    }

    public byte[] getEncoded() {
        return encoded;
    }

    public X509ResourceCertificate getCertificate() {
        return resourceCertificate;
    }

    public ASN1ObjectIdentifier getContentType() {
        return contentType;
    }

    public @Nullable Instant getSigningTime() {
        return signingTime;
    }

}
