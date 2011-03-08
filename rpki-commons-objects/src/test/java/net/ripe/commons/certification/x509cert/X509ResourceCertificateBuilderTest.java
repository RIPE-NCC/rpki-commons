package net.ripe.commons.certification.x509cert;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.rfc3779.ResourceExtensionEncoder;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

public class X509ResourceCertificateBuilderTest {

    private X509ResourceCertificateBuilder subject;

    @Before
    public void setUp() {
        subject = new X509ResourceCertificateBuilder();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(DateTimeZone.UTC);
        subject.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear()+1,1,1,0,0,0,0, DateTimeZone.UTC)));
        subject.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    }

    @Test
    public void shouldUseOnlyTheEncodedFormOfThePublicKey() {
        PublicKey publicKey = new PublicKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getFormat() {
                throw new UnsupportedOperationException();
            }

            @Override
            public byte[] getEncoded() {
                return TEST_KEY_PAIR.getPublic().getEncoded();
            }

            @Override
            public String getAlgorithm() {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean equals(Object obj) {
                throw new UnsupportedOperationException();
            }
        };

        subject.withPublicKey(publicKey);
        
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireResourcesForResourceCertificates() {
        subject.withResources(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireNonEmptyResourceSetForResourceCertificates() {
        subject.withResources(IpResourceSet.parse(""));
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireIssuer() {
        subject.withIssuerDN(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSubject() {
        subject.withSubjectDN(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSerial() {
        subject.withSerial(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequirePublicKey() {
        subject.withPublicKey(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSigningKeyPair() {
        subject.withSigningKeyPair(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireValidityPeriod() {
        subject.withValidityPeriod(null);
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldNotAllowKeyCertSignForNonCAs() {
        subject.withCa(false);
        subject.withKeyUsage(KeyUsage.keyCertSign);
        subject.buildResourceCertificate();
    }

    @Test
    public void shouldSetBasicConstraintsForCAs() {
        subject.withCa(true);
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertEquals(Integer.MAX_VALUE, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldNotSetBasicConstraintsForNonCAs() {
        subject.withCa(false);
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldHaveSubjectKeyIdentifierForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8"));
        subject.withSubjectKeyIdentifier(true);
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertNotNull(certificate.getSubjectKeyIdentifier());
    }

    @Test
    public void shouldHaveAuthorityKeyIdentifierForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8"));
        subject.withAuthorityKeyIdentifier(true);
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertNotNull(certificate.getAuthorityKeyIdentifier());
    }

    @Test
    public void shouldHaveResourceExtensionForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8, AS123"));
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertNotNull(certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS));
        assertNotNull(certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS));
    }

    @Test
    public void shouldHaveKeyUsageIfSet() {
        subject.withCa(true);
        subject.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        subject.withResources(IpResourceSet.parse("10/8"));
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertNotNull(certificate.getCertificate().getKeyUsage());
    }

    @Test
    public void shouldHaveCrlDistributionPoints() {
        URI crlURI = URI.create("rsync://foo/bar.crl");
        subject.withCrlDistributionPoints(crlURI);
        X509ResourceCertificate certificate = subject.buildResourceCertificate();

        assertEquals(crlURI, certificate.getCrlDistributionPoints()[0]);
    }

    @Test(expected=X509ResourceCertificateBuilderException.class)
    public void shouldFailOnIncorrectProvider() {
        subject.withSignatureProvider("foo");
        subject.buildResourceCertificate();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldFailOnIncorrectAlgorithm() {
        subject.withSignatureAlgorithm("foo");
        subject.buildResourceCertificate();
    }
}

