package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParserTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.assertj.core.api.Assertions.assertThat;


public class RoaCmsTest {

    public static final X500Principal TEST_DN = new X500Principal("CN=issuer");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;
    public static final URI TEST_ROA_LOCATION = URI.create("rsync://certificate/repository/filename.roa");
    static final URI CRL_DP = URI.create("rsync://certificate/repository/filename.crl");
    public static final BigInteger ROA_CERT_SERIAL = BigInteger.TEN;

    private List<RoaPrefix> ipv4Prefixes;
    private List<RoaPrefix> allPrefixes;
    private IpResourceSet allResources;
    private RoaCms subject;


    @Before
    public void setUp() {
        ipv4Prefixes = new ArrayList<>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);
        allPrefixes = new ArrayList<>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);
        allResources = new IpResourceSet();
        for (RoaPrefix prefix : allPrefixes) {
            allResources.add(prefix.getPrefix());
        }
        subject = createRoaCms(allPrefixes);
    }

    public static RoaCms createRoaCms(List<RoaPrefix> prefixes) {
        RoaCmsBuilder builder = new RoaCmsBuilder();
        builder.withCertificate(createCertificate(prefixes)).withAsn(TEST_ASN);
        builder.withPrefixes(prefixes);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    public static X509ResourceCertificate createCertificate(List<RoaPrefix> prefixes){
        return createCertificate(prefixes, TEST_KEY_PAIR);
    }
    public static X509ResourceCertificate createCertificate(List<RoaPrefix> prefixes, KeyPair keyPair) {
        IpResourceSet resources = new IpResourceSet();
        for (RoaPrefix prefix : prefixes) {
            resources.add(prefix.getPrefix());
        }
        X509ResourceCertificateBuilder builder = createCertificateBuilder(resources, keyPair);
        return builder.build();
    }

    private static X509ResourceCertificateBuilder createCertificateBuilder(IpResourceSet resources) {
            return createCertificateBuilder(resources, TEST_KEY_PAIR);
    }
    private static X509ResourceCertificateBuilder createCertificateBuilder(IpResourceSet resources, KeyPair keyPair) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(ROA_CERT_SERIAL);
        builder.withPublicKey(keyPair.getPublic());
        builder.withSigningKeyPair(keyPair);
        builder.withKeyUsage(KeyUsage.digitalSignature);
        var now = OffsetDateTime.now(ZoneOffset.UTC);
        builder.withValidityPeriod(new ValidityPeriod(now.minusMinutes(1), now.plusYears(1)));
        builder.withResources(resources);
        builder.withCrlDistributionPoints(CRL_DP);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_ROA_LOCATION));
        return builder;
    }

    @Test
    public void shouldGenerateRoaCms() {
        assertThat(TEST_ASN).isEqualTo(subject.getAsn());
        // prefixes in ROA are sorted, but allprefixes is not (yet)
        assertThat(allPrefixes.stream().sorted().collect(Collectors.toList())).isEqualTo(subject.getPrefixes());
        assertThat(allResources).isEqualTo(subject.getResources());
    }

    @Test
    public void shouldEncodeUniquePrefixes() {
        var doubledPrefixes = new ArrayList<RoaPrefix>();
        doubledPrefixes.addAll(allPrefixes);
        doubledPrefixes.addAll(allPrefixes);
        assertThat(doubledPrefixes.size()).isEqualTo(2*allPrefixes.size());

        var res = createRoaCms(doubledPrefixes);
        // allPrefixes is not sorted, so compare w/o considering order.
        // The order of prefixes is covered above
        assertThat(allPrefixes).containsExactlyInAnyOrderElementsOf(res.getPrefixes());
    }

    @Test
    public void shouldVerifySignature() {
        assertThat(subject.signedBy(subject.getCertificate())).isTrue();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectCaCertificateInRoa() {
        X509ResourceCertificate caCert = createCertificateBuilder(new IpResourceSet(TEST_IPV4_PREFIX_1.getPrefix(), TEST_IPV4_PREFIX_2.getPrefix(), TEST_IPV6_PREFIX.getPrefix())).withCa(true).build();
        subject = new RoaCmsBuilder().withAsn(TEST_ASN).withPrefixes(allPrefixes).withCertificate(caCert).build(TEST_KEY_PAIR.getPrivate());
    }

    @Test
    public void shouldUseNotValidBeforeTimeForSigningTime() {
        RoaCms roaCms = createRoaCms(allPrefixes);
        assertThat(roaCms.getCertificate().getValidityPeriod().notValidBefore()).isEqualTo(roaCms.getSigningTime());
    }

    @Test
    public void shouldPastValidityTimeForCmsBeTheSameAsTheCertificate() {
        assertThat(subject.getCertificate().isPastValidityTime(Instant.now())).isEqualTo(subject.isPastValidityTime(Instant.now()));
    }

    @Test
    public void shouldBeRevoked() {
        CertificateRepositoryObjectValidationContext validationContext = new CertificateRepositoryObjectValidationContext(
            subject.getParentCertificateUri(), subject.getCertificate());
        X509Crl crl = X509CrlTest.getCrlBuilder(Instant.now())
                .withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic())
                .addEntry(ROA_CERT_SERIAL, Instant.now().minus(1, ChronoUnit.DAYS))
                .build(TEST_KEY_PAIR.getPrivate());

        CrlLocator crlLocator = Mockito.mock(CrlLocator.class);
        Mockito.when(crlLocator.getCrl(Mockito.any(URI.class), Mockito.any(CertificateRepositoryObjectValidationContext.class), Mockito.any(ValidationResult.class))).thenReturn(crl);

        subject.validate(TEST_ROA_LOCATION.toString(), validationContext, crlLocator, ValidationOptions.strictValidation(), ValidationResult.withLocation(TEST_ROA_LOCATION));

        assertThat(subject.isRevoked()).isTrue().withFailMessage("ROA must be revoked");
    }

    @Test
    public void shouldNotBeRevoked() {
        CertificateRepositoryObjectValidationContext validationContext = new CertificateRepositoryObjectValidationContext(
            subject.getParentCertificateUri(), subject.getCertificate());
        X509Crl crl = X509CrlTest.getCrlBuilder(Instant.now())
                .withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic())
                .addEntry(ROA_CERT_SERIAL.add(BigInteger.ONE), Instant.now().minus(1, ChronoUnit.DAYS))
                .build(TEST_KEY_PAIR.getPrivate());

        CrlLocator crlLocator = Mockito.mock(CrlLocator.class);
        Mockito.when(crlLocator.getCrl(Mockito.any(URI.class), Mockito.any(CertificateRepositoryObjectValidationContext.class), Mockito.any(ValidationResult.class))).thenReturn(crl);

        subject.validate(TEST_ROA_LOCATION.toString(), validationContext, crlLocator, ValidationOptions.strictValidation(), ValidationResult.withLocation(TEST_ROA_LOCATION));

        assertThat(subject.isRevoked()).isFalse().withFailMessage("ROA must not be revoked");
    }
}
