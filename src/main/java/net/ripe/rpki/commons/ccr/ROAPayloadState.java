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
 * The ROA Payload State structure containing <code>rps</code> and <code>hash</code>.
 *
 * <pre>
 *    ROAPayloadState  ::= SEQUENCE {
 *      rps             SEQUENCE OF ROAPayloadSet,
 *      hash            Digest }
 * </pre>
 */
public record ROAPayloadState(
    List<ROAPayloadSet> rps,
    Sha256Digest hash
) implements ASN1Encodable {
    public static ROAPayloadState from(Collection<ROAPayloadSet> rps) {
        var vrps = rps.stream().sorted(Comparator.comparing(ROAPayloadSet::asID)).toList();
        var der = new DERSequence(vrps.toArray(ASN1Encodable[]::new));
        var hash = Sha256Digest.from(HashAlgorithms.sha256Digest(der));
        return new ROAPayloadState(vrps, hash);
    }

    public static ROAPayloadState decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var rps = decoder.take(ASN1Sequence.class);
        var hash = decoder.take(ASN1OctetString.class);
        return new ROAPayloadState(
            Stream.of(rps.toArray()).map(ROAPayloadSet::decode).toList(),
            Sha256Digest.from(hash.getOctets())
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{
            new DERSequence(
                rps.toArray(ASN1Encodable[]::new)
            ),
            hash
        });
    }
}
