package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * The Router Key structure containing <code>ski</code> and <code>spki</code>.
 *
 * <pre>
 *    RouterKey  ::= SEQUENCE {
 *      ski               SubjectKeyIdentifier,
 *      spki              SubjectPublicKeyInfo }
 * </pre>
 */
public record RouterKey(
        SubjectKeyIdentifier ski,
        SubjectPublicKeyInfo spki
) implements ASN1Encodable {
    public static RouterKey decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var ski = decoder.take(DEROctetString.class);
        var spki = decoder.take(DLSequence.class);
        return new RouterKey(SubjectKeyIdentifier.getInstance(ski), SubjectPublicKeyInfo.getInstance(spki));
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{
                ski.toASN1Primitive(),
                spki.toASN1Primitive()
        });
    }
}
