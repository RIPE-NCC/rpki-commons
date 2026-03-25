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
 * The ASPA Payload State structure containing <code>aps</code> and a <code>hash</code>.
 *
 * <pre>
 *    ASPAPayloadState  ::= SEQUENCE {
 *      aps               SEQUENCE OF ASPAPayloadSet,
 *      hash              Digest }
 * </pre>
 */
public record ASPAPayloadState(
    List<ASPAPayloadSet> aps,
    Sha256Digest hash
) implements ASN1Encodable {
    public static ASPAPayloadState from(Collection<ASPAPayloadSet> vaps) {
        var aps = vaps.stream().sorted(Comparator.comparingLong(ASPAPayloadSet::customerASID)).toList();
        var der = new DERSequence(aps.toArray(ASN1Encodable[]::new));
        var hash = Sha256Digest.from(HashAlgorithms.sha256Digest(der));
        return new ASPAPayloadState(aps, hash);
    }


    public static ASPAPayloadState decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var aps = decoder.take(ASN1Sequence.class);
        var hash = decoder.take(ASN1OctetString.class);
        return new ASPAPayloadState(
            Stream.of(aps.toArray()).map(ASPAPayloadSet::decode).toList(),
            Sha256Digest.from(hash.getOctets())
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{
            new DERSequence(aps.toArray(ASN1Encodable[]::new)),
            hash
        });
    }
}
