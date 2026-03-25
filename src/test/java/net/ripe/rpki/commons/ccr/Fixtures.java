package net.ripe.rpki.commons.ccr;

import lombok.experimental.UtilityClass;
import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.ccr.asn1.Sha256Digest;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT;
import static org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier;

@UtilityClass
public class Fixtures {
    private static final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    public static final Sha256Digest fakeHash = Sha256Digest.from(new byte[0]);
    public static final SubjectKeyIdentifier sampleSki = new SubjectKeyIdentifier(TEST_KEY_PAIR.getPublic().getEncoded());
    public static final ManifestInstance sampleManifest = new ManifestInstance(fakeHash, 1024, new DEROctetString(new byte[20]), BigInteger.valueOf(1), now, List.of(new AccessDescription(ID_AD_SIGNED_OBJECT, new GeneralName(uniformResourceIdentifier, "rsync://example.com/rpki/repository/1.mft"))), Optional.of(List.of(sampleSki)));

    public static final ManifestState sampleMfts = ManifestState.from(List.of(sampleManifest));

    public static final ROAPayloadState sampleRPipv4 = new ROAPayloadState(List.of(new ROAPayloadSet(2L, Optional.of(List.of(new ROAIPAddress(IpRange.parse("1.2.2.13/32"), Optional.of(32)), new ROAIPAddress(IpRange.parse("185.11.84.0/22"), Optional.of(22)), new ROAIPAddress(IpRange.parse("92.119.92.0/22"), Optional.of(22)))), Optional.empty()), new ROAPayloadSet(0L, Optional.of(List.of(new ROAIPAddress(IpRange.parse("1.2.2.13/32"), Optional.of(32)), new ROAIPAddress(IpRange.parse("185.11.84.0/22"), Optional.of(22)), new ROAIPAddress(IpRange.parse("92.119.92.0/22"), Optional.of(22)))), Optional.empty())), fakeHash);
    public static final ROAPayloadState sampleRPipv6 = ROAPayloadState.from(List.of(new ROAPayloadSet(0L, Optional.empty(), Optional.of(List.of(new ROAIPAddress(IpRange.parse("2a03:4800::/40"), Optional.of(22)), new ROAIPAddress(IpRange.parse("2a03:4800:100::/40"), Optional.of(40)), new ROAIPAddress(IpRange.parse("2a03:ca40::/32"), Optional.of(32)))))));

    public static final ASPAPayloadState sampleAP = ASPAPayloadState.from(List.of(new ASPAPayloadSet(0, List.of(1L, 5L, 7L))));

    public static final TrustAnchorState sampleTrustAnchorState = TrustAnchorState.from(List.of(sampleSki));

    public static final RouterKey sampleRouterKey = new RouterKey(sampleSki, SubjectPublicKeyInfo.getInstance(TEST_KEY_PAIR.getPublic().getEncoded()));

    public static final RouterKeyState sampleRouterKeyState = RouterKeyState.from(List.of(new RouterKeySet(0, List.of(sampleRouterKey))));

    public static final RPKICanonicalCacheRepresentation sampleCcr = new RPKICanonicalCacheRepresentation(now, Optional.of(sampleMfts), Optional.of(sampleRPipv6), Optional.of(sampleAP), Optional.of(sampleTrustAnchorState), Optional.of(sampleRouterKeyState));

    public static byte[] ccrSampleDer() throws IOException {
        var file = Fixtures.class.getResource("/ccr/draft-ietf-sidrops-rpki-ccr-03.ccr").getPath();
        return Base64.getMimeDecoder().decode(Files.readAllBytes(Path.of(file)));
    }
}
