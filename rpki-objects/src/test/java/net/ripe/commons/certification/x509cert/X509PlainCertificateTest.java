package net.ripe.commons.certification.x509cert;

import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Test;

public class X509PlainCertificateTest {

    // NOTE: Apparently the @After time restore in the TimeManipulatingTestCase may not be finished before other
    // tests are started.. resulting in validation failures: expired. That's why we changed +1 year here to +100 years
    // so future generations beware ;)
    private static final ValidityPeriod TEST_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(100));
    public static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=Test External Trust Anchor, CN=RIPE NCC, C=NL");
    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);

    public static X509CertificateBuilder createSelfSignedCaCertificateBuilder() {
        X509CertificateBuilder builder = createBasicBuilder();
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign);
        return builder;
    }

    public static X509CertificateBuilder createSelfSignedEeCertificateBuilder() {
        return createBasicBuilder().withCa(false);
    }

    private static X509CertificateBuilder createBasicBuilder() {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        builder.withAuthorityKeyIdentifier(true);
        return builder;
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldNotSupportResources() {
        createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.parse("10.0.0.0/8")).buildPlainCertificate();
    }



}
