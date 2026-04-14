package net.ripe.rpki.commons.ccr;

import net.ripe.ipresource.IpRange;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static net.ripe.rpki.commons.ccr.Fixtures.*;
import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;

class RPKICanonicalCacheRepresentationTest {
    private static final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    @Test
    void it_produces_an_empty_ccr_file() {
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        var der = encode(ccr);
        Assertions.assertTrue(der.length > 0, "DER encoded CCR must not be empty");
    }

    @Test
    void decode_over_encode_results_in_an_identical_object() {
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        var der = encode(ccr);
        var decoded = RPKICanonicalCacheRepresentation.decode(der);
        Assertions.assertEquals(ccr, decoded);
    }

    @Test
    void it_includes_manifest_state() {
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.of(sampleMfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertEquals(ccr, RPKICanonicalCacheRepresentation.decode(encode(ccr)));
    }

    @Test
    void it_includes_vrps() {
        var vrps = ROAPayloadState.from(sampleRPipv4.rps());
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.empty(), Optional.of(vrps), Optional.empty(), Optional.empty(), Optional.empty());
        Assertions.assertEquals(ccr, RPKICanonicalCacheRepresentation.decode(encode(ccr)));
    }

    @Test
    void it_includes_vaps() {
        var aps = ASPAPayloadState.from(sampleAP.aps());
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.empty(), Optional.empty(), Optional.of(aps), Optional.empty(), Optional.empty());
        Assertions.assertEquals(ccr, RPKICanonicalCacheRepresentation.decode(encode(ccr)));
    }

    @Test
    void it_includes_tas() {
        var tas = TrustAnchorState.from(sampleTrustAnchorState.skis());
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(tas), Optional.empty());
        Assertions.assertEquals(ccr, RPKICanonicalCacheRepresentation.decode(encode(ccr)));
    }

    @Test
    void it_includes_rksets() {
        var rksets = RouterKeyState.from(sampleRouterKeyState.rksets());
        var ccr = new RPKICanonicalCacheRepresentation(now, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(rksets));
        Assertions.assertEquals(ccr, RPKICanonicalCacheRepresentation.decode(encode(ccr)));
    }

    @Nested
    class RPKI_CCR_draft_03 {
        @Test
        void it_decodes_manifests() throws IOException {
            var ccr = RPKICanonicalCacheRepresentation.decode(ccrSampleDer());
            Assertions.assertTrue(ccr.mfts().isPresent(), "Manifests are not read.");
        }

        @Test
        void it_decodes_VRPs() throws IOException {
            var ccr = RPKICanonicalCacheRepresentation.decode(ccrSampleDer());
            Assertions.assertTrue(ccr.vrps().isPresent(), "VRPs are not read.");
        }

        @Test
        void it_decodes_ASPA_state() throws IOException {
            var ccr = RPKICanonicalCacheRepresentation.decode(ccrSampleDer());
            Assertions.assertTrue(ccr.vaps().isPresent(), "ASPA state is not read.");
        }

        @Test
        void it_decodes_TA_state() throws IOException {
            var ccr = RPKICanonicalCacheRepresentation.decode(ccrSampleDer());
            Assertions.assertTrue(ccr.tas().isPresent(), "TA state is not read.");
        }

        @Test
        void it_decodes_router_key_state() throws IOException {
            var ccr = RPKICanonicalCacheRepresentation.decode(ccrSampleDer());
            Assertions.assertTrue(ccr.rks().isPresent(), "Router key state is not read.");
        }

        @Test
        void encode_over_decode_is_identical_to_input() throws IOException {
            var input = ccrSampleDer();
            var ccr = RPKICanonicalCacheRepresentation.decode(input);
            var encoded = encode(ccr);
            Assertions.assertArrayEquals(input, encoded);
        }
    }

    @Nested
    class ManifestInstanceTests {
        @Test
        void decode_over_encode_results_in_an_identical_object() {
            var mft = sampleManifest;
            var der = encode(mft);
            Assertions.assertEquals(mft, ManifestInstance.decode(expect(decode(der), ASN1Sequence.class)));
        }
    }

    @Nested
    class ROAPayloadSetTests {
        @Test
        void decode_over_encode_results_in_identical_object_ipv4_only() {
            var rps = sampleRPipv4;
            var der = encode(rps);
            Assertions.assertEquals(rps, ROAPayloadState.decode(expect(decode(der), ASN1Sequence.class)));
        }

        @Test
        void decode_over_encode_results_in_identical_object_ipv6_only() {
            var rps = sampleRPipv6;
            var der = encode(rps);
            Assertions.assertEquals(rps, ROAPayloadState.decode(expect(decode(der), ASN1Sequence.class)));
        }

        @Test
        void decode_over_encode_results_in_identical_object_both_v4_and_v6() {
            var rps = new ROAPayloadState(List.of(new ROAPayloadSet(sampleRPipv4.rps().get(0).asID(), sampleRPipv4.rps().get(0).ipv4AddrBlocks(), sampleRPipv6.rps().get(0).ipv6AddrBlocks())), fakeHash);
            var der = encode(rps);
            Assertions.assertEquals(rps, ROAPayloadState.decode(expect(decode(der), ASN1Sequence.class)));
        }

        @Test
        void from_collection_sorts_ROA_Payload_state() {
            var asIDTwo = new ROAPayloadSet(2L, Optional.of(List.of(new ROAIPAddress(IpRange.parse("1.2.2.13/32"), Optional.of(32)), new ROAIPAddress(IpRange.parse("185.11.84.0/22"), Optional.of(22)), new ROAIPAddress(IpRange.parse("92.119.92.0/22"), Optional.of(22)))), Optional.empty());
            var asIDZero = new ROAPayloadSet(0L, Optional.of(List.of(new ROAIPAddress(IpRange.parse("1.2.2.13/32"), Optional.of(32)), new ROAIPAddress(IpRange.parse("185.11.84.0/22"), Optional.of(22)), new ROAIPAddress(IpRange.parse("92.119.92.0/22"), Optional.of(22)))), Optional.empty());
            var rps = ROAPayloadState.from(List.of(asIDTwo, asIDZero));
            Assertions.assertEquals(List.of(asIDZero, asIDTwo), rps.rps());
        }

        @Test
        void from_collection_sorts_ipv4blocks() {
            var ipv4BlockSmaller = new ROAIPAddress(IpRange.parse("31.149.0.0/16"), Optional.empty());
            var ipv4BlockBigger = new ROAIPAddress(IpRange.parse("31.160.0.0/15"), Optional.empty());
            var rps = ROAPayloadSet.from(0L, Optional.of(List.of(ipv4BlockBigger, ipv4BlockSmaller)), Optional.empty());
            Assertions.assertEquals(Optional.of(List.of(ipv4BlockSmaller, ipv4BlockBigger)), rps.ipv4AddrBlocks());
        }

        @Test
        void from_collection_sorts_ipv6blocks() {
            var ipv6BlockSmaller = new ROAIPAddress(IpRange.parse("2001:67c:1d4::/48"), Optional.empty());
            var ipv6BlockBigger = new ROAIPAddress(IpRange.parse("2a03:ca40::/32"), Optional.empty());
            var rps = ROAPayloadSet.from(0L, Optional.empty(), Optional.of(List.of(ipv6BlockBigger, ipv6BlockSmaller)));
            Assertions.assertEquals(Optional.of(List.of(ipv6BlockSmaller, ipv6BlockBigger)), rps.ipv6AddrBlocks());
        }
    }

    @Nested
    class ASPAPayloadStateTests {
        @Test
        void from_sorts_ASPAPayload_sets() {
            var asIDZero = new ASPAPayloadSet(0, List.of(1L, 5L, 7L));
            var asIDFour = new ASPAPayloadSet(4, List.of(1L, 5L, 7L));
            var aps = ASPAPayloadState.from(List.of(asIDFour, asIDZero));
            Assertions.assertEquals(List.of(asIDZero, asIDFour), aps.aps());
        }
    }

    @Nested
    class ASPAPayloadSetTests {
        @Test
        void decode_over_encode_results_in_identical_object() {
            var aps = sampleAP;
            var der = encode(aps);
            Assertions.assertEquals(aps, ASPAPayloadState.decode(expect(decode(der), ASN1Sequence.class)));
        }
    }

    @Nested
    class TrustAnchorStateTests {
        @Test
        void decode_over_encode_results_in_identical_object() {
            var tas = sampleTrustAnchorState;
            var der = encode(tas);
            Assertions.assertEquals(tas, TrustAnchorState.decode(expect(decode(der), ASN1Sequence.class)));
        }

        @Test
        void from_sorts_Trust_Anchor_State() {
            var zero = new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray());
            var one = new SubjectKeyIdentifier(BigInteger.ONE.toByteArray());
            var taSets = TrustAnchorState.from(List.of(one, zero));
            Assertions.assertEquals(List.of(zero, one), taSets.skis());
        }
    }

    @Nested
    class RouterKeyStateTests {
        @Test
        void decode_over_encode_results_in_identical_object() {
            var rksets = sampleRouterKeyState;
            var der = encode(rksets);
            Assertions.assertEquals(rksets, RouterKeyState.decode(expect(decode(der), ASN1Sequence.class)));
        }

        @Test
        void from_sorts_ROA_Payload_sets() {
            var asIDZero = new RouterKeySet(0, List.of(new RouterKey(sampleSki, SubjectPublicKeyInfo.getInstance(TEST_KEY_PAIR.getPublic().getEncoded()))));
            var asIDFour = new RouterKeySet(4, List.of(new RouterKey(sampleSki, SubjectPublicKeyInfo.getInstance(TEST_KEY_PAIR.getPublic().getEncoded()))));
            var rks = RouterKeyState.from(List.of(asIDFour, asIDZero));
            Assertions.assertEquals(List.of(asIDZero, asIDFour), rks.rksets());
        }
    }

    @Nested
    class RouterKeySetTests {
        @Test
        void from_sorts_Router_Keys() {
            var zero = new RouterKey(new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray()), sampleRouterKey.spki());
            var one = new RouterKey(new SubjectKeyIdentifier(BigInteger.ONE.toByteArray()), sampleRouterKey.spki());
            var rksets = RouterKeySet.from(0, List.of(one, zero));
            Assertions.assertEquals(List.of(zero, one), rksets.routerKeys());
        }
    }
}
