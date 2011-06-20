package net.ripe.commons.provisioning.x509;

import static net.ripe.commons.provisioning.ProvisioningObjectMother.*;
import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.junit.Before;
import org.junit.Test;

public class ProvisioningIdentityCertificateBuilderTest {

    private ProvisioningIdentityCertificateBuilder subject;

    public static final X500Principal SELF_SIGNING_DN = new X500Principal("CN=test");
    public static final KeyPair TEST_IDENTITY_KEYPAIR = TEST_KEY_PAIR;
    public static final KeyPair TEST_IDENTITY_KEYPAIR_2 = TEST_KEY_PAIR_2;
    public static final ProvisioningIdentityCertificate TEST_IDENTITY_CERT = getTestProvisioningIdentityCertificate();
    public static final ProvisioningIdentityCertificate TEST_IDENTITY_CERT_2 = getProvisioningIdentityCertificateForKey2();

    private static ProvisioningIdentityCertificate getTestProvisioningIdentityCertificate() {
        return getTestBuilder(TEST_IDENTITY_KEYPAIR).build();
    
    }
    
    private static ProvisioningIdentityCertificate getProvisioningIdentityCertificateForKey2() {
        return getTestBuilder(TEST_IDENTITY_KEYPAIR_2).build();
    }

    private static ProvisioningIdentityCertificateBuilder getTestBuilder(KeyPair keyPair) {
        ProvisioningIdentityCertificateBuilder identityCertificateBuilder = new ProvisioningIdentityCertificateBuilder();
        identityCertificateBuilder.withSelfSigningKeyPair(keyPair);
        identityCertificateBuilder.withSelfSigningSubject(SELF_SIGNING_DN);
        return identityCertificateBuilder;
    }


    @Before
    public void setUp() {
        // Create a builder with all requirements so that we can exclude (nullify) each
        // requirement for easy unit testing of the builder
        subject = getTestBuilder(TEST_IDENTITY_KEYPAIR);
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
     * No CRL. These certs are not published.
     */
    @Test
    public void shouldHaveNoRsyncCrlPointer() {
        assertNull(TEST_IDENTITY_CERT.findFirstRsyncCrlDistributionPoint());
    }

    /**
     * Self signed so should NOT have AIA pointer
     */
    @Test
    public void shouldNotHaveAiaPointer() {
        assertNull(TEST_IDENTITY_CERT.getAuthorityInformationAccess());
    }

    /**
     * No SIA. These certs are not published.
     */
    @Test
    public void shouldHaveSiaPointerToDirectoryOnly() {
        assertNull(TEST_IDENTITY_CERT.getSubjectInformationAccess());
    }

    @Test
    public void shouldBeACACertificate() {
        assertTrue(TEST_IDENTITY_CERT.isCa());
    }

    @Test
    public void shouldIncludeKeyUsageBitsCertSignAndCrlCertSign() {
        boolean[] keyUsage = TEST_IDENTITY_CERT.getCertificate().getKeyUsage();
        assertNotNull(keyUsage);
        // For KeyUsage flags order see bouncy castle KeyUsage class
        assertTrue(Arrays.equals(new boolean[] { false, false, false, false, false, true, true, false, false }, keyUsage));
    }
}

