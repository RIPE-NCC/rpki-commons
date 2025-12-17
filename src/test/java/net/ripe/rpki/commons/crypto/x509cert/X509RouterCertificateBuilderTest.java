package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionParser;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertificateParsingException;
import java.util.List;

import static net.ripe.rpki.commons.crypto.rfc8209.RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class X509RouterCertificateBuilderTest {
    private X509RouterCertificateBuilder subject;

    public static X509RouterCertificateBuilder createSelfSignedRouterCertificateBuilder() {
        X509RouterCertificateBuilder builder = new X509RouterCertificateBuilder();
        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withPublicKey(KeyPairFactoryTest.TEST_EC_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        builder.withAsns(new int[]{65536});
        DateTime now = UTC.dateTime();
        builder.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        return builder;
    }

    @Before
    public void setUp() {
        subject = createSelfSignedRouterCertificateBuilder();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireResourcesForResourceCertificates() {
        subject.withAsns(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireNonEmptyResourceSetForResourceCertificates() {
        subject.withAsns(new int[]{});
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireIssuer() {
        subject.withIssuerDN(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSubject() {
        subject.withSubjectDN(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSerial() {
        subject.withSerial(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequirePublicKey() {
        subject.withPublicKey(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSigningKeyPair() {
        subject.withSigningKeyPair(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireValidityPeriod() {
        subject.withValidityPeriod(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowKeyCertSignForNonCAs() {
        subject.withCa(false);
        subject.withKeyUsage(KeyUsage.keyCertSign);
        subject.build();
    }

    @Test
    public void shouldHaveExtendedKeyUsage() throws CertificateParsingException {
        final X509RouterCertificate x509RouterCertificate = subject.build();
        final List<String> extendedKeyUsage = x509RouterCertificate.getCertificate().getExtendedKeyUsage();
        assertEquals(1, extendedKeyUsage.size());
        assertEquals(OID_KP_BGPSEC_ROUTER.toString(), extendedKeyUsage.get(0));
    }

    @Test
    public void shouldIgnoreBasicConstraintsForCAs() {
        subject.withCa(true);
        X509RouterCertificate certificate = subject.build();
        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldNotSetBasicConstraintsForNonCAs() {
        subject.withCa(false);
        X509RouterCertificate certificate = subject.build();
        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldHaveCrlDistributionPoints() {
        URI crlURI = URI.create("rsync://foo/bar.crl");
        subject.withCrlDistributionPoints(crlURI);
        X509RouterCertificate certificate = subject.build();

        assertEquals(crlURI, certificate.getCrlDistributionPoints()[0]);
    }

    @Test
    public void shouldHaveAsnExtension() {
        subject.withAsns(new int[]{1, 22, 333});
        X509RouterCertificate certificate = subject.build();

        byte[] asnExtension = certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId());
        final IpResourceSet asResources = new ResourceExtensionParser().parseAsIdentifiers(asnExtension);
        assertEquals(IpResourceSet.parse("AS1, AS22, AS333"), asResources);
    }

    @Test
    public void shouldHaveBgpExtension() {
        subject.withAsns(new int[]{1, 22, 333});
        X509RouterCertificate certificate = subject.build();
        assertTrue(certificate.isRouter());
    }

    @Test(expected = X509ResourceCertificateBuilderException.class)
    public void shouldFailOnIncorrectProvider() {
        subject.withSignatureProvider("foo");
        subject.build();
    }
}
