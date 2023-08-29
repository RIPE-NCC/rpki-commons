package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumSet;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper.POLICY_INFORMATION;
import static org.junit.Assert.assertNull;


public class X509CertificateBuilderHelperTest {
    public final static PolicyInformation CAB_BASELINE_REQUIREMENTS_POLICY = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.2.2"));

    private X509CertificateBuilderHelper subject;

    @Before
    public void setUp() {
        subject = new X509CertificateBuilderHelper();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        var now = OffsetDateTime.now(ZoneOffset.UTC);
        subject.withValidityPeriod(new ValidityPeriod(now, OffsetDateTime.of(now.getYear() + 1, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC)));
        subject.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnIncorrectAlgorithm() {
        subject.withSignatureAlgorithm("foo");
        subject.generateCertificate();
    }

    @Test
    public void shouldMakeSureTheresNoExtendedKeyUsage() throws CertificateParsingException {
        final X509Certificate x509Certificate = subject.generateCertificate();
        assertNull(x509Certificate.getExtendedKeyUsage());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnEmptyResources() {
        subject.withResources(new IpResourceSet());
        subject.generateCertificate();
    }

    @Test
    public void shouldNotFailOnOneInheritResourceType() {
        subject.withResources(new IpResourceSet());
        subject.withInheritedResourceTypes(EnumSet.of(IpResourceType.IPv4));
        subject.generateCertificate();
    }

    public void shouldAcceptArbitraryPolicyWhichShouldBeCritical() {
        // Take a non-RPKI policy
        subject.withPolicies(CAB_BASELINE_REQUIREMENTS_POLICY);
        // And ensure it is critical
        subject.generateCertificate().getCriticalExtensionOIDs().contains(CAB_BASELINE_REQUIREMENTS_POLICY.getPolicyIdentifier().toString());
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOnRepeatedPolicies() {
        // Policy is set once (e.g. in constructor of supertype).
        subject.withPolicies(POLICY_INFORMATION);
        // And further attempts to set it are rejected (e.g. in an subtype).
        subject.withPolicies(CAB_BASELINE_REQUIREMENTS_POLICY);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnNegativeSerial() {
        subject.withSerial(BigInteger.ONE.negate());
        subject.generateCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnNeutralIntegerSerial() {
        subject.withSerial(BigInteger.ZERO);
        subject.generateCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnTooLargeSerial() {
        subject.withSerial(BigInteger.ONE.shiftLeft(160));
        subject.generateCertificate();
    }
}
