package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.Sha256Digest;
import net.ripe.rpki.commons.ccr.internal.HashAlgorithms;
import org.bouncycastle.asn1.*;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * The Router Key State structure containing <code>rksets</code> and a <code>hash</code>.
 *
 * <pre>
 *    RouterKeyState     ::= SEQUENCE {
 *      rksets      SEQUENCE OF RouterKeySet,
 *      hash        Digest }
 * </pre>
 */
public record RouterKeyState(
        List<RouterKeySet> rksets,
        Sha256Digest hash
) implements ASN1Encodable {
    public static RouterKeyState from(Collection<RouterKeySet> rksets) {
        var rks = rksets.stream().sorted(Comparator.comparingInt(RouterKeySet::asID)).toList();
        var der = new DERSequence(
                rks.toArray(ASN1Encodable[]::new)
        );
        var hash = Sha256Digest.from(HashAlgorithms.sha256Digest(der));
        return new RouterKeyState(rks, hash);
    }
    public static RouterKeyState decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var rksets = decoder.take(ASN1Sequence.class);
        var hash = decoder.take(ASN1OctetString.class);
        return new RouterKeyState(
                Stream.of(rksets.toArray()).map(RouterKeySet::decode).toList(),
                Sha256Digest.from(hash.getOctets())
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{
                new DERSequence(rksets.toArray(RouterKeySet[]::new)),
                hash
        });
    }
}
