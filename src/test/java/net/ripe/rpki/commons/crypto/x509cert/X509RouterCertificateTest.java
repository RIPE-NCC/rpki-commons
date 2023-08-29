package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class X509RouterCertificateTest {

    private static final URI MFT_URI = URI.create("rsync://host.foo/bar/ta.mft");
    private static final URI PUB_DIR_URI = URI.create("rsync://host.foo/bar/");

    public static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=TEST-SELF-SIGNED-CERT");

    private static final ValidityPeriod TEST_VALIDITY_PERIOD;

    static {
        var now = OffsetDateTime.now(ZoneOffset.UTC);
        TEST_VALIDITY_PERIOD = new ValidityPeriod(now.minusMinutes(1), now.plusYears(100));
    }

    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);

    public static X509RouterCertificateBuilder createBasicBuilder() {
        X509RouterCertificateBuilder builder = new X509RouterCertificateBuilder();
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        builder.withAuthorityKeyIdentifier(true);
        builder.withAsns(new int[] {1, 22, 333});
        return builder;
    }

    public static X509RouterCertificateBuilder createSelfSignedRouterCertificateBuilder() {
        return createBasicBuilder().withCa(false)
                .withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME)
                .withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireCertificate() {
        new X509RouterCertificate(null);
    }

    @Test
    public void shouldSupportCaCertificate() {
        X509RouterCertificate cert = createSelfSignedRouterCertificateBuilder().build();
        assertFalse(cert.isCa());
        assertTrue(cert.isRouter());
    }

    @Test
    public void shouldSupportAuthorityInformationAccessExtension() throws URISyntaxException {
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, new URI("rsync://foo.host/bar/baz.cer")),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, new URI("http://foo.host/bar/baz.cer"))
        };
        X509RouterCertificateBuilder builder = createSelfSignedRouterCertificateBuilder();
        builder.withAuthorityInformationAccess(descriptors);
        X509RouterCertificate cert = builder.build();
        assertArrayEquals(descriptors, cert.getAuthorityInformationAccess());

        assertEquals(descriptors[0].getLocation(), cert.findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS));
        assertNull(cert.findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST));
        assertNotNull(cert.findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS));
    }

    @Test
    public void shouldSupportSubjectInformationAccessExtension() throws URISyntaxException {
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, new URI("rsync://foo.host/bar/")),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, new URI("http://foo.host/bar/"))
        };
        X509RouterCertificateBuilder builder = createSelfSignedRouterCertificateBuilder();
        builder.withSubjectInformationAccess(descriptors);
        X509RouterCertificate cert = builder.build();
        assertArrayEquals(descriptors, cert.getSubjectInformationAccess());
        assertNotNull(cert.findFirstSubjectInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY));
    }

    @Test
    public void shouldSupportCrlDistributionPoints() {
        URI[] crlDistributionPoints = {
                URI.create("rsync://localhost/ca.crl")
        };
        X509RouterCertificateBuilder builder = createSelfSignedRouterCertificateBuilder();
        builder.withCrlDistributionPoints(crlDistributionPoints);
        X509RouterCertificate cert = builder.build();
        assertArrayEquals(crlDistributionPoints, cert.getCrlDistributionPoints());
        assertNotNull(cert.findFirstRsyncCrlDistributionPoint());
    }

    @Test
    public void shouldHaveValidSignature() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509RouterCertificate certificate = createSelfSignedRouterCertificateBuilder().build();
        certificate.getCertificate().verify(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
    }

    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidSignature() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509RouterCertificate certificate = createSelfSignedRouterCertificateBuilder().build();
        certificate.getCertificate().verify(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());
    }

}
