package net.ripe.commons.provisioning.x509;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;

import org.junit.Test;

public class ProvisioningIdentityCertificateTest {
    
    public static final KeyPair TEST_KEY_PAIR = ProvisioningKeyPairGenerator.generate();
    public static final X500Principal SELF_SIGNING_DN = new X500Principal("CN=test");
    public static final ProvisioningIdentityCertificate TEST_PROVISIONING_IDENTITY_CERTIFICATE;
    
    static {
        ProvisioningIdentityCertificateBuilder identityCertificateBuilder = new ProvisioningIdentityCertificateBuilder();
        TEST_PROVISIONING_IDENTITY_CERTIFICATE = identityCertificateBuilder.build(TEST_KEY_PAIR, SELF_SIGNING_DN);
    }


    @Test(expected=IllegalArgumentException.class)
    public void shouldCheckForNullArgument() {
        new ProvisioningIdentityCertificate(null);
    }

    @Test
    public void shouldWrapX509Certificate() {
        assertTrue(TEST_PROVISIONING_IDENTITY_CERTIFICATE.getCertificate() instanceof X509Certificate);
    }

}
