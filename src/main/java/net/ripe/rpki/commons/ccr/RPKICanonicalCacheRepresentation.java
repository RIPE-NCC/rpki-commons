package net.ripe.rpki.commons.ccr;

import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceDecoder;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.ccr.asn1.InvalidContent;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256;


/**
 * The Canonical Cache Representation (CCR) that represents the various aspects of the state of a validated cache.
 *
 * <p>
 * The validated cache contains all RPKI objects that the Relying Party (RP) has verified to be valid according to
 * the RPKI validation rules.
 * </p>
 *
 * <pre>
 *    RpkiCanonicalCacheRepresentation ::= SEQUENCE {
 *      version     [0] INTEGER DEFAULT 0,
 *      hashAlg         DigestAlgorithmIdentifier,
 *
 *      producedAt      GeneralizedTime,
 *      mfts        [1] ManifestState OPTIONAL,
 *      vrps        [2] ROAPayloadState OPTIONAL,
 *      vaps        [3] ASPAPayloadState OPTIONAL,
 *      tas         [4] TrustAnchorState OPTIONAL,
 *      rks         [5] RouterKeyState OPTIONAL,
 *      ... }
 *      -- at least one of mfts, vrps, vaps, tas, or rks MUST be present
 *      ( WITH COMPONENTS { ..., mfts PRESENT } |
 *        WITH COMPONENTS { ..., vrps PRESENT } |
 *        WITH COMPONENTS { ..., vaps PRESENT } |
 *        WITH COMPONENTS { ..., tas PRESENT } |
 *        WITH COMPONENTS { ..., rks PRESENT } )
 * </pre>
 */
public record RPKICanonicalCacheRepresentation(
        Instant producedAt,
        Optional<ManifestState> mfts,
        Optional<ROAPayloadState> vrps,
        Optional<ASPAPayloadState> vaps,
        Optional<TrustAnchorState> tas,
        Optional<RouterKeyState> rks
) implements ASN1Encodable {
    private static final int TAGNO_CONTENT = 0;
    private static final int TAGNO_MFTS = 1;
    private static final int TAGNO_VRPS = 2;
    private static final int TAGNO_VAPS = 3;
    private static final int TAGNO_TAS = 4;
    private static final int TAGNO_RKS = 5;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.54");

    public static RPKICanonicalCacheRepresentation decode(byte[] der) {
        try (var asn1 = new ASN1InputStream(der)) {
            var content = decodeContentInfo(expect(asn1.readObject(), ASN1Sequence.class));
            return decode(expect(content, ASN1Sequence.class));
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot decode CCR object from ASN1 data", e);
        }
    }

    private static ASN1Object decodeContentInfo(ASN1Sequence contentInfo) {
        var contentType = expect(contentInfo.getObjectAt(0), ASN1ObjectIdentifier.class);
        if (!OID.equals(contentType)) {
            throw InvalidContent.unexpectedValue("OID", OID.getId(), contentType.getId());
        }
        var content = expect(contentInfo.getObjectAt(1), DLTaggedObject.class);
        if (content.getTagNo() != TAGNO_CONTENT) {
            throw InvalidContent.unexpectedValue("explicit content tag", String.valueOf(TAGNO_CONTENT), String.valueOf(content.getTagNo()));
        }
        return content.getExplicitBaseObject();
    }

    public static RPKICanonicalCacheRepresentation decode(ASN1Sequence content) {
        var decoder = ASN1SequenceDecoder.from(content);
        var maybeVersion = decoder.takeOptional(ASN1Integer.class);
        maybeVersion.ifPresent(version -> {
            if (!version.getValue().equals(BigInteger.ZERO)) {
                throw InvalidContent.unexpectedValue("version", String.valueOf(maybeVersion), String.valueOf(0));
            }
        });
        var hashAlg = decoder.take(ASN1Sequence.class);
        var digestAlg = expect(hashAlg.getObjectAt(0), ASN1ObjectIdentifier.class);
        if (!digestAlg.equals(id_sha256)) {
            throw InvalidContent.unexpectedValue("hashAlg", id_sha256.getId(), digestAlg.getId());
        }
        var producedAt = decoder.takeTime();
        var mfts = decoder.takeTaggedOptional(TAGNO_MFTS);
        var vrps = decoder.takeTaggedOptional(TAGNO_VRPS);
        var vaps = decoder.takeTaggedOptional(TAGNO_VAPS);
        var tas = decoder.takeTaggedOptional(TAGNO_TAS);
        var rks = decoder.takeTaggedOptional(TAGNO_RKS);
        return new RPKICanonicalCacheRepresentation(
                producedAt,
                mfts.map(x -> ManifestState.decode(expect(x, ASN1Sequence.class))),
                vrps.map(x -> ROAPayloadState.decode(expect(x, ASN1Sequence.class))),
                vaps.map(x -> ASPAPayloadState.decode(expect(x, ASN1Sequence.class))),
                tas.map(x -> TrustAnchorState.decode(expect(x, ASN1Sequence.class))),
                rks.map(x -> RouterKeyState.decode(expect(x, ASN1Sequence.class)))
        );
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return ASN1SequenceEncoder.encode(
            OID,
            new DERTaggedObject(
                true,
                TAGNO_CONTENT,
                ASN1SequenceEncoder
                    .start(
                        ASN1SequenceEncoder.encode(id_sha256),
                        new ASN1GeneralizedTime(Date.from(producedAt))
                    )
                    .append(mfts.map(explicitlyTagged(TAGNO_MFTS)))
                    .append(vrps.map(explicitlyTagged(TAGNO_VRPS)))
                    .append(vaps.map(explicitlyTagged(TAGNO_VAPS)))
                    .append(tas.map(explicitlyTagged(TAGNO_TAS)))
                    .append(rks.map(explicitlyTagged(TAGNO_RKS)))
                    .encode()
            )
        );
    }

    private static Function<ASN1Encodable, DERTaggedObject> explicitlyTagged(int tagno) {
        return content -> new DERTaggedObject(true, tagno, content);
    }
}
