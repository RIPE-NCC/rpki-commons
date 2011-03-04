package net.ripe.commons.provisioning.x509;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

public class ProvisioningIdentityCertificateTest {
    
    public static final KeyPair TEST_KEY_PAIR = generateKeyPair(2048);
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

    public static KeyPair generateKeyPair(int size) {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            generator.initialize(new RSAKeyGenParameterSpec(size, RSAKeyGenParameterSpec.F4));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
}
