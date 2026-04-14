package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.ccr.internal.Sorting;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * The Router Key Set structure containing an <code>asID</code> and <code>routerKeys</code>.
 *
 * <pre>
 *    RouterKey  ::= SEQUENCE {
 *      asID              Integer,
 *      routerKeys        SEQUENCE (SIZE(1..MAX)) OF RouterKey }
 * </pre>
 */
public record RouterKeySet(
        int asID,
        List<RouterKey> routerKeys
) implements ASN1Encodable {
    public static RouterKeySet from(int asID, List<RouterKey> routerKeys) {
        return new RouterKeySet(
                asID,
                routerKeys.stream().sorted(Comparator.comparing(RouterKey::ski, Sorting.ski)).toList()
        );
    }

    public static RouterKeySet decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var asID = decoder.take(ASN1Integer.class);
        var routerKeys = decoder.take(ASN1Sequence.class);
        return new RouterKeySet(
                asID.getValue().intValueExact(),
                Stream.of(routerKeys.toArray()).map(RouterKey::decode).toList()
        );
    }
    @Override
    public ASN1Primitive toASN1Primitive() {
        return ASN1SequenceEncoder.encode(
            new ASN1Integer(asID),
            ASN1SequenceEncoder.encode(routerKeys)
        );
    }
}
