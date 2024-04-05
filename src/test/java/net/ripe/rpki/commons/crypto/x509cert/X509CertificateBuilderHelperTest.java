package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper.POLICY_INFORMATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


public class X509CertificateBuilderHelperTest {
    public final static PolicyInformation CAB_BASELINE_REQUIREMENTS_POLICY = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.2.2"));

    private X509CertificateBuilderHelper subject;

    @BeforeEach
    public void setUp() {
        subject = new X509CertificateBuilderHelper();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = UTC.dateTime();
        subject.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        subject.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    }

    @Test
    public void shouldFailOnIncorrectAlgorithm() {
        subject.withSignatureAlgorithm("foo");
        assertThatThrownBy(() -> subject.generateCertificate())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void shouldMakeSureTheresNoExtendedKeyUsage() throws CertificateParsingException {
        final X509Certificate x509Certificate = subject.generateCertificate();
        assertThat(x509Certificate.getExtendedKeyUsage()).isNull();
    }

    @Test
    public void shouldFailOnEmptyResources() {
        subject.withResources(new IpResourceSet());
        assertThatThrownBy(() -> subject.generateCertificate())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void shouldNotFailOnOneInheritResourceType() {
        subject.withResources(new IpResourceSet());
        subject.withInheritedResourceTypes(EnumSet.of(IpResourceType.IPv4));
        assertThat(subject.generateCertificate()).isNotNull();
    }

    @Test
    public void shouldAcceptArbitraryPolicyWhichShouldBeCritical() {
        // Take a non-RPKI policy
        subject.withPolicies(CAB_BASELINE_REQUIREMENTS_POLICY);
        // And ensure it is critical
        assertThat(subject.generateCertificate().getCriticalExtensionOIDs()).contains(Extension.certificatePolicies.toString());
    }

    @Test
    public void shouldFailOnRepeatedPolicies() {
        // Policy is set once (e.g. in constructor of supertype).
        subject.withPolicies(POLICY_INFORMATION);
        // And further attempts to set it are rejected (e.g. in an subtype).
        assertThatThrownBy(() -> subject.withPolicies(CAB_BASELINE_REQUIREMENTS_POLICY))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void shouldFailOnNegativeSerial() {
        subject.withSerial(BigInteger.ONE.negate());
        assertThatThrownBy(() -> subject.generateCertificate())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void shouldFailOnNeutralIntegerSerial() {
        subject.withSerial(BigInteger.ZERO);
        assertThatThrownBy(() -> subject.generateCertificate())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void shouldFailOnTooLargeSerial() {
        subject.withSerial(BigInteger.ONE.shiftLeft(160));
        assertThatThrownBy(() -> subject.generateCertificate())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
