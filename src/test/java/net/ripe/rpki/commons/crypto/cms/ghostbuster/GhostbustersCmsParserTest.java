package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Ignore;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static net.ripe.rpki.commons.validation.ValidationString.GHOSTBUSTERS_RECORD_SINGLE_VCARD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;

public class GhostbustersCmsParserTest {

    private static final X500Principal TEST_DN = new X500Principal("CN=issuer");
    private static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;
    private static final URI TEST_ROA_LOCATION = URI.create("rsync://certificate/repository/filename.roa");
    private static final URI TEST_CA_LOCATION = URI.create("rsync://certificate/repository/ca.cer");
    private static final URI CRL_DP = URI.create("rsync://certificate/repository/filename.crl");
    private static final BigInteger ROA_CERT_SERIAL = BigInteger.TEN;

    @Ignore("This GBR actually does not conform to the RFC")
    @Test
    public void testShouldParseGoodGbr() throws Exception {
        String path = "src/test/resources/conformance/root/goodRealGbrNothingIsWrong.gbr";
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation("test1.gbr"), bytes);

        GhostbustersCms ghostbustersCms = parser.getResult().orElseThrow();
        String vCard = ghostbustersCms.getVCardContent();
        assertEquals("""
            BEGIN:VCARD\r
            VERSION:3.0\r
            ADR:;;5147 Crystal Springs Drive NE;Bainbridge Island;Washington;98110;Uni\r
             ted States\r
            EMAIL:randy@psg.com\r
            FN:Randy Bush\r
            N:;;;;\r
            ORG:RGnet\\, LLC\r
            TEL:+1 206 356 8341\r
            END:VCARD\r
            """, vCard);
    }

    @Test
    public void ghostbusters_record_must_have_vcard() {
        ValidationResult validationResult = validatePayload("");

        assertThat(validationResult.hasFailures()).isTrue();
        assertThat(validationResult.getFailuresForCurrentLocation())
            .anyMatch(c -> GHOSTBUSTERS_RECORD_SINGLE_VCARD.equals(c.getKey()));
    }

    @Test
    public void ghostbusters_record_must_have_single_vcard() {
        ValidationResult validationResult = validatePayload("""
            BEGIN:VCARD\r
            END:VCARD\r
            BEGIN:VCARD
            END:VCARD
            """);

        assertThat(validationResult.hasFailures()).isTrue();
        assertThat(validationResult.getFailuresForCurrentLocation())
            .anyMatch(c -> GHOSTBUSTERS_RECORD_SINGLE_VCARD.equals(c.getKey()));
    }

    private ValidationResult validatePayload(String vCardPayload) {
        byte[] ghostbustersCms = new GhostbustersCmsBuilder()
            .withCertificate(createCertificate())
            .withVCardPayload(vCardPayload)
            .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
            .getEncoded(TEST_KEY_PAIR.getPrivate());

        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        ValidationResult validationResult = ValidationResult.withLocation("test2.gbr");
        parser.parse(validationResult, ghostbustersCms);
        return validationResult;
    }

    @Test(expected = IllegalArgumentException.class)
    public void testShouldParseBadGbr() throws Exception {
        String path = "src/test/resources/conformance/root/badGBRNotVCard.gbr";
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation("test2.gbr"), bytes);
        parser.getResult().orElseThrow(IllegalArgumentException::new);
    }

    private static X509ResourceCertificate createCertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(ROA_CERT_SERIAL);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withKeyUsage(KeyUsage.digitalSignature);
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        var now = ZonedDateTime.now(ZoneOffset.UTC);
        builder.withValidityPeriod(new ValidityPeriod(now.minusMinutes(1), now.plusYears(1)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        builder.withCrlDistributionPoints(CRL_DP);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_ROA_LOCATION));
        builder.withAuthorityInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, TEST_CA_LOCATION));
        return builder.build();
    }
}
