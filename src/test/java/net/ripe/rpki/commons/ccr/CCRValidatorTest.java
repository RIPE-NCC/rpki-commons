package net.ripe.rpki.commons.ccr;

import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.ccr.asn1.ASN1SequenceEncoder;
import net.ripe.rpki.commons.ccr.asn1.Sha256Digest;
import net.ripe.rpki.commons.ccr.internal.HashAlgorithms;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static java.time.Instant.now;
import static net.ripe.rpki.commons.ccr.Fixtures.*;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CCRValidatorTest {
    @Test
    void rfc_sample_is_valid() throws Exception {
        var ccr = RPKICanonicalCacheRepresentation.decode(ccrSampleDer());
        assertDoesNotThrow(() -> CCRValidator.validate(ccr));
    }

    @Test
    void sample_fixture_passes_all_rules() {
        assertDoesNotThrow(() -> CCRValidator.validate(sampleCcr));
    }

    @Test
    void it_requires_at_least_one_payload() {
        var empty = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        assertThrows(InvalidState.class, () -> CCRValidator.validate(empty));
    }

    @Nested
    class ManifestStateValidations {
        @Test
        void it_checks_instance_order() {
            var mis = List.of(
                    new ManifestInstance(Sha256Digest.from(new byte[] { 1 }), 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), sampleManifest.subordinates()),
                    new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), sampleManifest.subordinates())
            );
            var hash = HashAlgorithms.sha256Digest(ASN1SequenceEncoder.encode(mis));
            var mru = sampleManifest.thisUpdate();
            var mfts = new ManifestState(mis, mru, Sha256Digest.from(hash));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_manifest_state_for_duplicate_hashes() {
            var mi = new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), sampleManifest.subordinates());
            var mis = List.of(mi, mi);
            var mfts = ManifestState.from(mis);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_mostRecentUpdate() {
            var mis = List.of(
                    new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), Instant.now().truncatedTo(ChronoUnit.SECONDS), sampleManifest.locations(), sampleManifest.subordinates())
            );
            var hash = HashAlgorithms.sha256Digest(ASN1SequenceEncoder.encode(mis));
            var mfts = new ManifestState(mis, Instant.EPOCH.truncatedTo(ChronoUnit.SECONDS), Sha256Digest.from(hash));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_hash() {
            var mis = List.of(
                    new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), sampleManifest.subordinates())
            );
            var mfts = new ManifestState(mis, sampleManifest.thisUpdate(), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }

    @Nested
    class ManifestInstanceValidations {
        @Test
        void it_checks_manifest_instance_size() {
            var mfts = ManifestState.from(List.of(new ManifestInstance(fakeHash, 900, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), sampleManifest.subordinates())));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_requires_manifest_instance_locations() {
            var mfts = ManifestState.from(List.of(new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), List.of(), sampleManifest.subordinates())));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_subordinates_for_duplicate_skis() {
            var subordinates = List.of(
                    new SubjectKeyIdentifier(BigInteger.ONE.toByteArray()),
                    new SubjectKeyIdentifier(BigInteger.ONE.toByteArray())
            );
            var mfts = ManifestState.from(List.of(new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), Optional.of(subordinates))));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_requires_manifest_instance_subordinates_when_present() {
            var mfts = ManifestState.from(List.of(new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), Optional.of(List.of()))));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_manifest_instance_subordinates_order() {
            var subordinates = List.of(
                    new SubjectKeyIdentifier(BigInteger.ONE.toByteArray()),
                    new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray())
            );
            var mfts = ManifestState.from(List.of(new ManifestInstance(fakeHash, 1024, sampleManifest.aki(), sampleManifest.manifestNumber(), sampleManifest.thisUpdate(), sampleManifest.locations(), Optional.of(subordinates))));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.of(mfts), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }

    @Nested
    class ROAPayloadSetValidations {
        @Test
        void it_checks_order_of_ROA_payload_sets() {
            var ipAddress = new ROAIPAddress(IpRange.parse("31.149.0.0/16"), Optional.empty());
            var rpsSmaller = new ROAPayloadSet(0L, Optional.of(List.of(ipAddress)), Optional.empty());
            var rpsBigger = new ROAPayloadSet(1L, Optional.of(List.of(ipAddress)), Optional.empty());
            var vrps = new ROAPayloadState(List.of(rpsBigger, rpsSmaller), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.of(vrps), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_requires_ip_block_presence() {
            var empty = new ROAPayloadSet(0L, Optional.empty(), Optional.empty());
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.of(ROAPayloadState.from(List.of(empty))), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_ROA_payload_sets_for_duplicate_asId() {
            var ipv4Block = new ROAIPAddress(IpRange.parse("31.149.0.0/16"), Optional.empty());
            var rps = new ROAPayloadSet(0L, Optional.of(List.of(ipv4Block)), Optional.empty());
            var vrps = ROAPayloadState.from(List.of(rps, rps));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.of(vrps), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_ipv4_block_order() {
            var ipv4BlockSmaller = new ROAIPAddress(IpRange.parse("31.149.0.0/16"), Optional.empty());
            var ipv4BlockBigger = new ROAIPAddress(IpRange.parse("31.160.0.0/15"), Optional.empty());
            var rps = new ROAPayloadSet(0L, Optional.of(List.of(ipv4BlockBigger, ipv4BlockSmaller)), Optional.empty());
            var vrps = new ROAPayloadState(List.of(rps), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.of(vrps), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_ipv6_block_order() {
            var ipv6BlockSmaller = new ROAIPAddress(IpRange.parse("2a03:4800::/40"), Optional.empty());
            var ipv6BlockBigger = new ROAIPAddress(IpRange.parse("2a03:ca40::/32"), Optional.empty());
            var rps = new ROAPayloadSet(0L, Optional.empty(), Optional.of(List.of(ipv6BlockBigger, ipv6BlockSmaller)));
            var vrps = new ROAPayloadState(List.of(rps), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.of(vrps), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_hash() {
            var rps = new ROAPayloadSet(0L, Optional.empty(), Optional.of(List.of(new ROAIPAddress(IpRange.parse("31.149.0.0/16"), Optional.empty()))));
            var vrps = new ROAPayloadState(List.of(rps), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.of(vrps), Optional.empty(), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }

    @Nested
    class ASPAPayloadStateValidations {
        @Test
        void it_checks_order_of_ASPA_payload_sets() {
            var asIDZero = new ASPAPayloadSet(0, List.of(1L, 5L, 7L));
            var asIDFour = new ASPAPayloadSet(4, List.of(1L, 5L, 7L));
            var aps = new ASPAPayloadState(List.of(asIDFour, asIDZero), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.of(aps), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_ASPA_payload_sets_for_duplicate_asId() {
            var asIDZero = new ASPAPayloadSet(4L, List.of(1L, 5L, 7L));
            var asIDFour = new ASPAPayloadSet(4L, List.of(1L, 8L, 13L));
            var aps = ASPAPayloadState.from(List.of(asIDFour, asIDZero));
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.of(aps), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_hash() {
            var aps = new ASPAPayloadState(List.of(new ASPAPayloadSet(4, List.of(1L, 5L, 7L))), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.of(aps), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }

    @Nested
    class ASPAPayloadSetValidations {
        @Test
        void it_requires_providers() {
            var empty = new ASPAPayloadSet(0, List.of());
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.of(ASPAPayloadState.from(List.of(empty))), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_order_of_providers() {
            var ap = new ASPAPayloadSet(0, List.of(5L, 2L, 7L));
            var aps = new ASPAPayloadState(List.of(ap), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.of(aps), Optional.empty(), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }

    @Nested
    class TrustAnchorStateValidations {
        @Test
        void it_requires_at_least_one_ski() {
            var tas = new TrustAnchorState(List.of(), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(tas), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_order_of_skis() {
            var zero = new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray());
            var one = new SubjectKeyIdentifier(BigInteger.ONE.toByteArray());
            var tas = new TrustAnchorState(List.of(one, zero), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(tas), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_hash() {
            var tas = new TrustAnchorState(List.of(new SubjectKeyIdentifier(BigInteger.ONE.toByteArray())), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(tas), Optional.empty());
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }

    @Nested
    class RouterKeyStateValidations {
        @Test
        void it_checks_hash() {
            var rk = new RouterKey(new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray()), sampleRouterKey.spki());
            var rks = new RouterKeyState(List.of(new RouterKeySet(0, List.of(rk))), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(rks));
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_router_key_state_for_duplicate_skis() {
            var rk = new RouterKey(new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray()), sampleRouterKey.spki());
            var rks = new RouterKeyState(List.of(new RouterKeySet(0, List.of(rk)), new RouterKeySet(0, List.of(rk))), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(rks));
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_requires_router_keys() {
            var empty = new RouterKeySet(0, List.of());
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(RouterKeyState.from(List.of(empty))));
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_router_key_sets_order() {
            var asIDZero = new RouterKeySet(0, List.of(new RouterKey(sampleSki, SubjectPublicKeyInfo.getInstance(TEST_KEY_PAIR.getPublic().getEncoded()))));
            var asIDFour = new RouterKeySet(4, List.of(new RouterKey(sampleSki, SubjectPublicKeyInfo.getInstance(TEST_KEY_PAIR.getPublic().getEncoded()))));
            var rks = new RouterKeyState(List.of(asIDFour, asIDZero), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(rks));
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }

        @Test
        void it_checks_router_keys_order() {
            var zero = new RouterKey(new SubjectKeyIdentifier(BigInteger.ZERO.toByteArray()), sampleRouterKey.spki());
            var one = new RouterKey(new SubjectKeyIdentifier(BigInteger.ONE.toByteArray()), sampleRouterKey.spki());
            var rksets = new RouterKeySet(0, List.of(one, zero));
            var rks = new RouterKeyState(List.of(rksets), fakeHash);
            var invalid = new RPKICanonicalCacheRepresentation(now(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(rks));
            assertThrows(InvalidState.class, () -> CCRValidator.validate(invalid));
        }
    }
}
