package net.ripe.rpki.commons.crypto.x509cert;

import com.google.common.io.Files;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;
import static net.ripe.rpki.commons.validation.ValidationString.CERTIFICATE_PARSED;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class X509RouterCertificateParserTest {

    private final X509RouterCertificateParser subject = new X509RouterCertificateParser();

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireResourceCertificatePolicy() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509CertificateBuilderTestUtils.setPoliciesOnBuilderHelperAttribute(builder);
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotParseResourceCertificateWhenResourceExtensionsArePresent() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test
    public void shouldFailOnInvalidInput() {
        byte[] badlyEncoded = {0x01, 0x03, 0x23};
        subject.parse("badly", badlyEncoded);
        assertTrue(subject.getValidationResult().getFailures(new ValidationLocation("badly")).contains(new ValidationCheck(ValidationStatus.ERROR, CERTIFICATE_PARSED)));
    }

    @Test
    public void shouldFailOnInvalidSignatureAlgorithm() throws CertificateEncodingException {
        X509CertificateBuilderHelper builder = new X509CertificateBuilderHelper();
        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        var now = ZonedDateTime.now(ZoneOffset.UTC);
        builder.withValidityPeriod(new ValidityPeriod(now, ZonedDateTime.of(now.getYear() + 1, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        builder.withSignatureAlgorithm("MD5withRSA");
        X509Certificate certificate = builder.generateCertificate();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().hasFailures());
        assertFalse(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.CERTIFICATE_SIGNATURE_ALGORITHM).isOk());
    }

    @Test
    public void should_validate_key_algorithm_and_size() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.PUBLIC_KEY_CERT_ALGORITHM).isOk());
        assertTrue(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.PUBLIC_KEY_CERT_SIZE).isOk());
    }

    @Test
    public void should_parse_the_real_router_certificate() throws IOException {
        byte[] encoded = Files.toByteArray(new File("src/test/resources/router/router_certificate.cer"));

        subject.parse("certificate", encoded);
        final ValidationResult validationResult = subject.getValidationResult();
        assertFalse(validationResult.hasFailureForCurrentLocation());
        final X509RouterCertificate certificate = subject.getCertificate();
        assertNotNull(certificate);
    }

}
