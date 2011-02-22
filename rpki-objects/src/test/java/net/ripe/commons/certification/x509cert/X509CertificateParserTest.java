package net.ripe.commons.certification.x509cert;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.joda.time.DateTime;
import org.junit.Test;


public class X509CertificateParserTest {

    private static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final IpResourceSet RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final ValidityPeriod TEST_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));

    private X509CertificateParser<? extends X509PlainCertificate> subject = X509CertificateParser.forPlainCertificate();

    public static X509CertificateBuilder createPreconfiguredBuilder() {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        configurePlainCertificateFields(builder);
        builder.withResources(RESOURCE_SET);
        builder.withAuthorityKeyIdentifier(false);
        return builder;
    }

	@Test
    public void shouldFailOnPlainCertificateWhenResourceCertificateIsRequired() throws CertificateEncodingException {
		subject = X509CertificateParser.forResourceCertificate();
	    subject.parse("certificate", createPlainCertificate().getEncoded());
	    assertTrue(subject.getValidationResult().hasFailures());
	    try {
	    	subject.getCertificate();
	    	fail("IllegalArgumentException expected");
	    } catch (IllegalArgumentException expect) {
	    	// expected
	    }
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireResourceCertificatePolicy() {
        X509CertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder().withPolicies(new PolicyInformation(new DERObjectIdentifier("1.2.3.4")));
        X509ResourceCertificate certificate = builder.buildResourceCertificate();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test
    public void shouldParseResourceCertificateWhenResourceExtensionsArePresent() {
        X509CertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.buildResourceCertificate();

        subject.parse("certificate", certificate.getEncoded());
        X509PlainCertificate parsed = subject.getCertificate();

        assertTrue(parsed instanceof X509ResourceCertificate);
        assertEquals(certificate, parsed);
    }

    @Test
    public void shouldParsePlainCertificateWhenResourceExtensionsAreAbsent() {
        X509PlainCertificate certificate = createPlainCertificate();

        subject.parse("certificate", certificate.getEncoded());
        X509PlainCertificate parsed = subject.getCertificate();

        assertEquals(X509PlainCertificate.class, parsed.getClass());
        assertEquals(certificate, parsed);
    }

    @Test
    public void shouldFailOnInvalidInput() {
        byte[] badlyEncoded = { 0x01, 0x03, 0x23 };
        X509CertificateParser<X509ResourceCertificate> parser = X509CertificateParser.forResourceCertificate();
        parser.parse("badly", badlyEncoded);
        assertEquals(Arrays.asList(new ValidationCheck(false, CERTIFICATE_PARSED)), parser.getValidationResult().getFailures("badly"));
    }

    @Test
    public void shouldFailOnInvalidSignatureAlgorithm() {
        X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder().withSignatureAlgorithm("MD5withRSA").buildResourceCertificate();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().hasFailures());
        assertTrue(subject.getValidationResult().hasFailuresForLocationAndKey("certificate", ValidationString.CERTIFICATE_SIGNATURE_ALGORITHM));
    }

    private static X509PlainCertificate createPlainCertificate() {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        configurePlainCertificateFields(builder);
        builder.withAuthorityKeyIdentifier(false);
        return builder.buildPlainCertificate();
    }

    private static void configurePlainCertificateFields(X509CertificateBuilder builder) {
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
    }
}
