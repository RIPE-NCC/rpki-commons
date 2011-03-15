package net.ripe.commons.provisioning.x509;

import static net.ripe.commons.provisioning.ProvisioningObjectMother.*;
import static org.junit.Assert.*;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;

import org.junit.Before;
import org.junit.Test;

public class ProvisioningIdentityCertificateBuilderTest {

    private ProvisioningIdentityCertificateBuilder subject;

    public static final X500Principal SELF_SIGNING_DN = new X500Principal("CN=test");
    public static final URI TEST_CRL_RSYNC_URI = URI.create("rsync://some.host:10873/camanagername/myid/id.crl");
    public static final URI TEST_SIA_RSYNC_URI = URI.create("rsync://some.host:10873/camanagername/myid/");
    public static final ProvisioningIdentityCertificate TEST_IDENTITY_CERT = getTestProvisioningIdentityCertificate();

    private static ProvisioningIdentityCertificate getTestProvisioningIdentityCertificate() {
        ProvisioningIdentityCertificateBuilder identityCertificateBuilder = getTestBuilder();
        return identityCertificateBuilder.build();
    }

    private static ProvisioningIdentityCertificateBuilder getTestBuilder() {
        ProvisioningIdentityCertificateBuilder identityCertificateBuilder = new ProvisioningIdentityCertificateBuilder();
        identityCertificateBuilder.withSelfSigningKeyPair(TEST_KEY_PAIR);
        identityCertificateBuilder.withSelfSigningSubject(SELF_SIGNING_DN);
        identityCertificateBuilder.withCrlRsyncUri(TEST_CRL_RSYNC_URI);
        identityCertificateBuilder.withRepositoryRsyncUri(TEST_SIA_RSYNC_URI);
        return identityCertificateBuilder;
    }


    @Before
    public void setUp() {
        // Create a builder with all requirements so that we can exclude (nullify) each
        // requirement for easy unit testing of the builder
        subject = getTestBuilder();
    }

    @Test
    public void shouldBuild() {
        ProvisioningIdentityCertificate identityCert = subject.build();
        assertNotNull(identityCert);
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSelfSigningKeyPair() {
        subject = new ProvisioningIdentityCertificateBuilder();
        subject.withSelfSigningSubject(ProvisioningIdentityCertificateBuilderTest.SELF_SIGNING_DN);
        subject.build();
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSelfSigningDN() {
        subject.withSelfSigningSubject(null);
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
        ProvisioningIdentityCertificate identityCert = subject.build();
        assertEquals("SHA256withRSA", identityCert.getCertificate().getSigAlgName());
    }

    /**
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldUse2048BitRsaKey() {
        assertTrue(TEST_IDENTITY_CERT.getPublicKey() instanceof RSAPublicKey);
        assertEquals(((RSAPublicKey) TEST_IDENTITY_CERT.getPublicKey()).getModulus().bitLength(), 2048);
    }

    /**
     * Requirements unclear in spec. Seems logical for now to require CRL
     */
    @Test
    public void shouldHaveOneRsyncCrlPointer() {
        assertNotNull(TEST_IDENTITY_CERT.findFirstRsyncCrlDistributionPoint());
    }

    /**
     * Self signed so should NOT have AIA pointer
     */
    @Test
    public void shouldNotHaveAiaPointer() {
        assertNull(TEST_IDENTITY_CERT.getAuthorityInformationAccess());
    }

    /**
     * One SIA pointer to directory, NO manifest
     */
    @Test
    public void shouldHaveSiaPointerToDirectoryOnly() {
        X509CertificateInformationAccessDescriptor[] subjectInformationAccess = TEST_IDENTITY_CERT.getSubjectInformationAccess();
        assertEquals(1, subjectInformationAccess.length);
    }

    @Test
    public void shouldBeACACertificate() {
        assertTrue(TEST_IDENTITY_CERT.isCa());
    }
}

