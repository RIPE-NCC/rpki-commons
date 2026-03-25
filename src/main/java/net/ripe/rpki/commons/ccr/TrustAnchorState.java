package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.Sha256Digest;
import net.ripe.rpki.commons.ccr.internal.HashAlgorithms;
import net.ripe.rpki.commons.ccr.internal.Sorting;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

/**
 * The Trust Anchor State represents the set of valid Trust Anchor (TA) Certification Authority (CA) resource certificates.
 *
 * <pre>
 *    TrustAnchorState     ::= SEQUENCE {
 *      skis        SEQUENCE (SIZE(1..MAX)) OF SubjectKeyIdentifier,
 *      hash        Digest }
 * </pre>
 */
public record TrustAnchorState(
        List<SubjectKeyIdentifier> skis,
        Sha256Digest hash
) implements ASN1Encodable {
    public static TrustAnchorState from(Collection<SubjectKeyIdentifier> skis) {
        var kis = skis.stream().sorted(Sorting.ski).toList();
        var der = new DERSequence(kis.toArray(ASN1Encodable[]::new));
        var hash = HashAlgorithms.sha256Digest(der);
        return new TrustAnchorState(kis, Sha256Digest.from(hash));
    }

    public static TrustAnchorState decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var skis = decoder.take(ASN1Sequence.class);
        var hash = decoder.take(ASN1OctetString.class);
        return new TrustAnchorState(
                Stream.of(skis.toArray()).map(SubjectKeyIdentifier::getInstance).toList(),
                Sha256Digest.from(hash.getOctets())
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{
                new DERSequence(skis.toArray(SubjectKeyIdentifier[]::new)),
                hash
        });
    }
}
