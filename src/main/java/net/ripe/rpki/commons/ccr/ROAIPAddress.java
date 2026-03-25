package net.ripe.rpki.commons.ccr;

import java.util.Optional;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;

import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.crypto.util.Asn1Util;

/**
 * The ROA IP Address structure containing an <code>address</code> and optional <code>maxLength</code>.
 *
 * <pre>
 *    ROAIPAddress {INTEGER: ub} ::= SEQUENCE {
 *      address       BIT STRING (SIZE(0..ub)),
 *      maxLength     INTEGER (0..ub) OPTIONAL }
 * </pre>
 */
record ROAIPAddress(
        IpRange address,
        Optional<Integer> maxLength
) implements ASN1Encodable {
    public static ROAIPAddress decode(ASN1Encodable asn1, IpResourceType family) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var address = Asn1Util.parseIpAddressAsPrefix(family, decoder.take());
        var maxLength = decoder.takeOptional(ASN1Integer.class);
        return new ROAIPAddress(
                address,
                maxLength.map(ASN1Integer::intValueExact)
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return ASN1SequenceEncoder
            .start(Asn1Util.encodeIpAddress(address))
            .append(maxLength.map(ASN1Integer::new))
            .encode();
    }
}
