package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.ccr.asn1.Sha256Digest;
import net.ripe.rpki.commons.ccr.internal.Sorting;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * The Manifest Instance structure containing a <code>hash</code>, <code>size</code>,
 * <code>aki</code>, <code>manifestNumber</code>, <code>thisUpdate</code>, <code>locations</code> and <code>subordinates</code>.
 *
 * <pre>
 *    ManifestInstance  ::= SEQUENCE {
 *      hash              Digest,
 *      size              INTEGER (1000..MAX),
 *      aki               KeyIdentifier,
 *      manifestNumber    INTEGER (0..MAX),
 *      thisUpdate        GeneralizedTime,
 *      locations         SEQUENCE (SIZE(1..MAX)) OF AccessDescription,
 *      subordinates      SEQUENCE (SIZE(1..MAX)) OF SubjectKeyIdentifier OPTIONAL }
 * </pre>
 */
public record ManifestInstance(
        Sha256Digest hash,
        int size,
        ASN1OctetString aki,
        BigInteger manifestNumber,
        Instant thisUpdate,
        List<AccessDescription> locations,
        Optional<List<SubjectKeyIdentifier>> subordinates
) implements ASN1Encodable {
    public static ManifestInstance from(
            Sha256Digest hash,
            int size,
            ASN1OctetString aki,
            BigInteger manifestNumber,
            Instant thisUpdate,
            List<AccessDescription> locations,
            Optional<List<SubjectKeyIdentifier>> subordinates
    ) {
        return new ManifestInstance(
                hash,
                size,
                aki,
                manifestNumber,
                thisUpdate,
                locations,
                subordinates.map(xs -> xs.stream().sorted(Sorting.ski).toList())
        );
    }

    public static ManifestInstance decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var hash = decoder.take(ASN1OctetString.class);
        var size = decoder.take(ASN1Integer.class);
        var aki = decoder.take(ASN1OctetString.class);
        var manifestNumber = decoder.take(ASN1Integer.class);
        var thisUpdate = decoder.takeTime();
        var locations = decoder.take(ASN1Sequence.class);
        var subordinates = decoder.takeOptional(ASN1Sequence.class);
        return new ManifestInstance(
                Sha256Digest.from(hash.getOctets()),
                size.getValue().intValueExact(),
                aki,
                manifestNumber.getValue(),
                thisUpdate,
                Stream.of(locations.toArray()).map(AccessDescription::getInstance).toList(),
                subordinates.map(seq -> Stream.of(seq.toArray()).map(SubjectKeyIdentifier::getInstance).toList())
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return ASN1SequenceEncoder
            .start(
                hash,
                new ASN1Integer(size),
                aki,
                new ASN1Integer(manifestNumber),
                new ASN1GeneralizedTime(Date.from(thisUpdate)),
                ASN1SequenceEncoder.encode(locations)
            )
            .append(subordinates.map(ASN1SequenceEncoder::encode))
            .encode();
    }
}
