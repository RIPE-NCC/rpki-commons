package net.ripe.rpki.commons.ccr;

import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.ccr.asn1.InvalidContent;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.*;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * The ROA Payload Set structure containing an <code>asId</code> and optional <code>ipv4AddrBlocks</code> and
 * <code>ipv6AddrBlocks</code>. One of the blocks MUST be present.
 *
 * <pre>
 *    ROAPayloadSet     ::= SEQUENCE {
 *      asID                Integer,
 *      ipv4AddrBlocks      SEQUENCE (SIZE(1..2)) OF ROAIPAddress OPTIONAL
 *      ipv6AddrBlocks      SEQUENCE (SIZE(1..2)) OF ROAIPAddress OPTIONAL }
 * </pre>
 */
public record ROAPayloadSet(Long asID, Optional<List<ROAIPAddress>> ipv4AddrBlocks,
                            Optional<List<ROAIPAddress>> ipv6AddrBlocks
) implements ASN1Encodable {
    static final short AFI_V4 = 1;
    static final short AFI_V6 = 2;

    public static ROAPayloadSet from(Long asID, Optional<List<ROAIPAddress>> ipv4AddrBlocks, Optional<List<ROAIPAddress>> ipv6AddrBlocks) {
        return new ROAPayloadSet(
                asID,
                ipv4AddrBlocks.map(ROAPayloadSet::sortIps),
                ipv6AddrBlocks.map(ROAPayloadSet::sortIps)
        );
    }

    private static List<ROAIPAddress> sortIps (List<ROAIPAddress> ips) {
        return ips.stream().sorted(Comparator.comparing(ROAIPAddress::address)).toList();
    }

    public static ROAPayloadSet decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var asID = decoder.take(ASN1Integer.class);
        var ipblocks = new ASN1SequenceDecoder(decoder.take(ASN1Sequence.class));
        var blocks = Stream.of(
            Optional.of(decodeIpAddrBlock(ipblocks.take(ASN1Sequence.class))),
            ipblocks.takeOptional(ASN1Sequence.class).map(ROAPayloadSet::decodeIpAddrBlock)
        ).flatMap(Optional::stream).collect(Collectors.groupingBy(Pair::getLeft));

        blocks.forEach((key, value) -> {
            if (value.size() > 1) {
                throw new InvalidContent("Multiple ipAddrBlocks found for address family %s".formatted(key));
            }
        });

        return new ROAPayloadSet(
            asID.getValue().longValueExact(),
            Optional.ofNullable(blocks.get(IpResourceType.IPv4)).map(x -> x.get(0).getRight()),
            Optional.ofNullable(blocks.get(IpResourceType.IPv6)).map(x -> x.get(0).getRight())
        );
    }

    private static Pair<IpResourceType, List<ROAIPAddress>> decodeIpAddrBlock(ASN1Sequence block) {
        var decoder = new ASN1SequenceDecoder(block);
        var afi = asShort(decoder.take(ASN1OctetString.class).getOctets());
        var family = asFamily(afi);
        var addrs = decoder.take(ASN1Sequence.class);
        return Pair.of(family, Stream.of(addrs.toArray()).map(x -> ROAIPAddress.decode(x, family)).toList());
    }

    private static IpResourceType asFamily(short afi) {
        return switch (afi) {
            case AFI_V4 -> IpResourceType.IPv4;
            case AFI_V6 -> IpResourceType.IPv6;
            default ->
                throw InvalidContent.unexpectedValue("AFI", "one of [%d, %d]".formatted(AFI_V4, AFI_V6), String.valueOf(afi));
        };
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return ASN1SequenceEncoder.encode(
            new ASN1Integer(asID),
            new ASN1SequenceEncoder()
                .append(ipv4AddrBlocks.map(block -> encodeIpBlock(AFI_V4, block)))
                .append(ipv6AddrBlocks.map(block -> encodeIpBlock(AFI_V6, block)))
                .encode()
        );
    }

    private ASN1Encodable encodeIpBlock(short afi, List<ROAIPAddress> block) {
        return ASN1SequenceEncoder.encode(asOctets(afi), ASN1SequenceEncoder.encode(block));
    }

    private ASN1OctetString asOctets(short n) {
        var hi = (byte) (n >> 8);
        var lo = (byte) n;
        return new DEROctetString(new byte[]{hi, lo});
    }

    private static short asShort(byte[] octets) {
        return (short) ((octets[0] << 8) | (octets[1] & 0xff));
    }
}
