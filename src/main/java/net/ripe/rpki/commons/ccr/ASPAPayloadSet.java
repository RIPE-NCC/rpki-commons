package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import org.bouncycastle.asn1.*;

import java.util.List;
import java.util.stream.Stream;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;

/**
 * The ASPA Payload Set structure containing <code>customerASID</code> and <code>providers</code>.
 *
 * <pre>
 *    ASPAPayloadSet  ::= SEQUENCE {
 *      customerASID      ASID,
 *      providers         SEQUENCE (SIZE(1..MAX)) OF ASID }
 * </pre>
 */
public record ASPAPayloadSet(
        long customerASID,
        List<Long> providers
) implements ASN1Encodable {
    public static ASPAPayloadSet from(long customerASID, List<Long> providers) {
        return new ASPAPayloadSet(
                customerASID,
                providers.stream().sorted().toList()
        );
    }
    public static ASPAPayloadSet decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var customerASID = decoder.take(ASN1Integer.class);
        var providers = decoder.take(ASN1Sequence.class);
        return new ASPAPayloadSet(
                customerASID.getValue().longValueExact(),
                Stream.of(providers.toArray())
                        .map(x -> expect(x, ASN1Integer.class).getValue().longValueExact())
                        .toList()
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(
                new ASN1Integer(customerASID),
                new DERSequence(providers.stream().map(ASN1Integer::new).toArray(ASN1Integer[]::new))
        );
    }
}
