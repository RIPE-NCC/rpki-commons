package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.ccr.asn1.Sha256Digest;
import net.ripe.rpki.commons.ccr.internal.HashAlgorithms;
import org.bouncycastle.asn1.*;

import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 *  An instance of ManifestState represents the set of valid, current
 *    Manifests ([RFC9286]) in the cache.  It contains three fields: <code>mis</code>,
 *    <code>mostRecentUpdate</code>, and <code>hash</code>.
 *
 * <pre>
 *    ManifestState  ::= SEQUENCE {
 *      mis               SEQUENCE OF ManifestInstance,
 *      mostRecentUpdate  GeneralizedTime,
 *      hash              Digest }
 * </pre>
 */
public record ManifestState(
        List<ManifestInstance> mis,
        Instant mostRecentUpdate,
        Sha256Digest hash
) implements ASN1Encodable {
    public static ManifestState from(Collection<ManifestInstance> mis) {
        var mostRecentUpdate = mis.stream()
                .map(ManifestInstance::thisUpdate)
                .reduce(BinaryOperator.maxBy(Comparator.comparing(Function.identity())))
                .orElse(Instant.EPOCH);
        var sorted = mis.stream().sorted(Comparator.comparing(ManifestInstance::hash)).toList();
        var misDer = ASN1SequenceEncoder.encode(sorted);
        return new ManifestState(
            sorted,
            mostRecentUpdate,
            Sha256Digest.from(HashAlgorithms.sha256Digest(misDer))
        );
    }

    public static ManifestState decode(ASN1Encodable asn1) {
        var decoder = ASN1SequenceDecoder.from(asn1);
        var mis = decoder.take(ASN1Sequence.class);
        var mostRecentUpdate = decoder.takeTime();
        var hash = decoder.take(ASN1OctetString.class);
        return new ManifestState(
                Stream.of(mis.toArray()).map(ManifestInstance::decode).toList(),
                mostRecentUpdate,
                Sha256Digest.from(hash.getOctets())
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return ASN1SequenceEncoder.encode(
            ASN1SequenceEncoder.encode(mis),
            new ASN1GeneralizedTime(Date.from(mostRecentUpdate)),
            hash
        );
    }
}
