package net.ripe.commons.provisioning.keypair;

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

public class ProvisioningKeyPairGeneratorTest {

    KeyPair testKeyPair = ProvisioningKeyPairGenerator.generate();
    
    @Test
    public void shouldUseRsa() {
        assertEquals("RSA", testKeyPair.getPrivate().getAlgorithm());
    }
    
    @Test
    public void shouldUse2048Bits() {
        RSAPublicKey publicKey = (RSAPublicKey) testKeyPair.getPublic();
        assertEquals(2048, publicKey.getModulus().bitLength());
    }
    
}
