package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * A ghostbusters RPKI object as defined in <a href="https://tools.ietf.org/html/rfc6493">RFC6493</a>.
 */
public class GhostbustersCms extends RpkiSignedObject {

    public static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.35");
    private final String vCardContent;

    GhostbustersCms(RpkiSignedObjectInfo cmsObjectData, String vCardContent) {
        super(cmsObjectData);
        this.vCardContent = vCardContent;
    }

    public String getVCardContent() {
        return vCardContent;
    }

    @Deprecated
    public String getvCard() {
        return vCardContent;
    }
}
