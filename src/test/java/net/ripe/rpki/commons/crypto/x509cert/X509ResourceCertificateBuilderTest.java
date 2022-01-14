package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static org.junit.Assert.*;

public class X509ResourceCertificateBuilderTest {

    private X509ResourceCertificateBuilder subject;

    @Before
    public void setUp() {
        subject = new X509ResourceCertificateBuilder();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = UTC.dateTime();
        subject.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        subject.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireResourcesForResourceCertificates() {
        subject.withResources(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireNonEmptyResourceSetForResourceCertificates() {
        subject.withResources(IpResourceSet.parse(""));
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
    public void shouldSetBasicConstraintsForCAs() {
        subject.withCa(true);
        X509ResourceCertificate certificate = subject.build();

        assertEquals(Integer.MAX_VALUE, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldNotSetBasicConstraintsForNonCAs() {
        subject.withCa(false);
        X509ResourceCertificate certificate = subject.build();

        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldHaveSubjectKeyIdentifierForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8"));
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getSubjectKeyIdentifier());
    }

    @Test
    public void shouldHaveAuthorityKeyIdentifierForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8"));
        subject.withAuthorityKeyIdentifier(true);
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getAuthorityKeyIdentifier());
    }

    @Test
    public void shouldHaveResourceExtensionForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8, AS123"));
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId()));
        assertNotNull(certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId()));
    }

    @Test
    public void shouldHaveKeyUsageIfSet() {
        subject.withCa(true);
        subject.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        subject.withResources(IpResourceSet.parse("10/8"));
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getCertificate().getKeyUsage());
    }

    @Test
    public void shouldHaveCrlDistributionPoints() {
        URI crlURI = URI.create("rsync://foo/bar.crl");
        subject.withCrlDistributionPoints(crlURI);
        X509ResourceCertificate certificate = subject.build();

        assertEquals(crlURI, certificate.getCrlDistributionPoints()[0]);
    }

    @Test(expected = X509ResourceCertificateBuilderException.class)
    public void shouldFailOnIncorrectProvider() {
        subject.withSignatureProvider("foo");
        subject.build();
    }


}
