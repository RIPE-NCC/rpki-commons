package net.ripe.rpki.commons.crypto.rfc8209;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import static net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder.OID_PKIX;

public class RouterExtensionEncoder {

    /**
     * id-kp OBJECT IDENTIFIER ::= {
     * iso(1) identified-organization(3) dod(6) internet(1)
     * security(5) mechanisms(5) pkix(7) kp(3) }
     * <p>
     * id-kp-bgpsec-router OBJECT IDENTIFIER ::= { id-kp 30 }
     */
    public static final String OID_KP = OID_PKIX + ".3";

    public static final ASN1ObjectIdentifier OID_KP_BGPSEC_ROUTER = new ASN1ObjectIdentifier(OID_KP + ".30");

}
