package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.util.UTC;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static net.ripe.rpki.commons.provisioning.ProvisioningObjectMother.*;
import static net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.*;
import static org.junit.Assert.*;

public class ProvisioningCmsCertificateBuilderTest {

    public static final KeyPair EE_KEYPAIR = KeyPairFactory.rsa().generate();

    public static final ProvisioningCmsCertificate TEST_CMS_CERT = getTestProvisioningCmsCertificate();

    private ProvisioningCmsCertificateBuilder subject;


    private static ProvisioningCmsCertificate getTestProvisioningCmsCertificate() {
        ProvisioningCmsCertificateBuilder cmsCertificateBuilder = getTestBuilder();
        return cmsCertificateBuilder.build();
    }

    private static ProvisioningCmsCertificateBuilder getTestBuilder() {
        ProvisioningCmsCertificateBuilder builder = new ProvisioningCmsCertificateBuilder();
        builder.withIssuerDN(TEST_IDENTITY_CERT.getSubject());
        builder.withSerial(BigInteger.TEN);
        builder.withPublicKey(EE_KEYPAIR.getPublic());
        builder.withSubjectDN(new X500Principal("CN=end-entity"));
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

    @Before
    public void setUp() {
        // Create a builder with all requirements so that we can exclude (nullify) each
        // requirement for easy unit testing of the builder
        subject = getTestBuilder();
    }

    @Test
    public void shouldBuild() {
        ProvisioningCmsCertificate cmsCertificate = subject.build();
        assertNotNull(cmsCertificate);
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequirePublicKey() {
        subject.withPublicKey(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireIssuerDN() {
        subject.withIssuerDN(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSubjectDN() {
        subject.withSubjectDN(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSerial() {
        subject.withSerial(null);
        subject.build();
    }

    // ======= the following unit tests test properties of the certificate built by this builder =====

    /**
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldUseSHA256withRSA() {
        assertEquals("SHA256withRSA", TEST_CMS_CERT.getCertificate().getSigAlgName());
    }

    @Test
    public void shouldUseProvidedSubjectKey() {
        assertEquals(EE_KEYPAIR.getPublic(), TEST_CMS_CERT.getCertificate().getPublicKey());
    }

    @Test
    public void shouldNotHaveRsyncCrlPointer() {
        assertNull(TEST_CMS_CERT.findFirstRsyncCrlDistributionPoint());
    }

    @Test
    public void shouldNotHaveAiaPointer() {
        assertNull(TEST_CMS_CERT.getAuthorityInformationAccess());
    }

    @Test
    public void shouldHaveNoSiaPointer() {
        X509CertificateInformationAccessDescriptor[] subjectInformationAccess = TEST_CMS_CERT.getSubjectInformationAccess();
        assertNull(subjectInformationAccess);
    }

    @Test
    public void shouldSetDefaultValidityPeriod() {
        final X509Certificate certificate = getTestProvisioningCmsCertificate().getCertificate();
        final Duration validityDuration = Duration.between(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        assertTrue(validityDuration.compareTo(Duration.ofDays(1)) == -1);
    }

    @Test
    public void shouldSetValidityPeriod() {
        final DateTime now = UTC.dateTime();
        final ValidityPeriod yearInDays = new ValidityPeriod(now, now.plusDays(365));

        final X509Certificate certificate = subject.withValidityPeriod(yearInDays).build().getCertificate();

        final Duration validityDuration = Duration.between(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        assertTrue(validityDuration.compareTo(Duration.ofDays(365)) == 0);
    }

    @Test
    public void shouldBeAnEECertificate() {
        assertFalse(TEST_CMS_CERT.isCa());
    }

    @Test
    public void shouldHaveKeyUsageExtensionDigitalSignature() {
        boolean[] keyUsage = TEST_CMS_CERT.getCertificate().getKeyUsage();
        // For KeyUsage flags order see bouncy castle KeyUsage class
        assertTrue(Arrays.equals(new boolean[]{true, false, false, false, false, false, false, false, false}, keyUsage));
    }
}

