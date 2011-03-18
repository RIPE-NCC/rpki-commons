package net.ripe.commons.provisioning.x509;

import static net.ripe.commons.provisioning.ProvisioningObjectMother.*;
import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;

import org.junit.Before;
import org.junit.Test;

public class ProvisioningCmsCertificateBuilderTest {

    public static final KeyPair EE_KEYPAIR = ProvisioningKeyPairGenerator.generate();

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
        builder.withCrlRsyncUri(URI.create("rsync://repository/parent-publication-dir/"));
        builder.withAuthorityInformationAccess(new X509CertificateInformationAccessDescriptor[] {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, URI.create("rsync://repository/member/identity-cert-publication-uri"))
        });
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

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequirePublicKey() {
        subject.withPublicKey(null);
        subject.build();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireIssuerDN() {
        subject.withIssuerDN(null);
        subject.build();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSubjectDN() {
        subject.withSubjectDN(null);
        subject.build();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSerial() {
        subject.withSerial(null);
        subject.build();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireAia() {
        subject.withAuthorityInformationAccess((X509CertificateInformationAccessDescriptor)null);
        subject.build();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireCrlRsyncUri() {
        subject.withCrlRsyncUri(null);
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

    /**
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldUse2048BitRsaKey() {
        assertTrue(TEST_CMS_CERT.getPublicKey() instanceof RSAPublicKey);
        assertEquals(((RSAPublicKey) TEST_CMS_CERT.getPublicKey()).getModulus().bitLength(), 2048);
    }

    @Test
    public void shouldHaveRsyncCrlPointer() {
        assertNotNull(TEST_CMS_CERT.findFirstRsyncCrlDistributionPoint());
    }

    @Test
    public void shouldHaveAiaPointer() {
        assertNotNull(TEST_CMS_CERT.getAuthorityInformationAccess());
    }

    @Test
    public void shouldHaveNoSiaPointer() {
        X509CertificateInformationAccessDescriptor[] subjectInformationAccess = TEST_CMS_CERT.getSubjectInformationAccess();
        assertNull(subjectInformationAccess);
    }

    @Test
    public void shouldBeAnEECertificate() {
        assertFalse(TEST_CMS_CERT.isCa());
    }

    @Test
    public void shouldHaveKeyUsageExtensionDigitalSignature() {
        boolean[] keyUsage = TEST_CMS_CERT.getCertificate().getKeyUsage();
        // For KeyUsage flags order see bouncy castle KeyUsage class
        assertTrue(Arrays.equals(new boolean[] { true, false, false, false, false, false, false, false, false }, keyUsage));
    }
}

