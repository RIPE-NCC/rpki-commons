package net.ripe.commons.provisioning.keypair;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

public class ProvisioningKeyPairGeneratorTest {

    KeyPair testKeyPair = ProvisioningKeyPairGenerator.generate();

    /**
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldUseRsaWithAlgorithm() {
        assertEquals("RSA", testKeyPair.getPrivate().getAlgorithm());
    }

    /**
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldUse2048Bits() {
        RSAPublicKey publicKey = (RSAPublicKey) testKeyPair.getPublic();
        assertEquals(2048, publicKey.getModulus().bitLength());
    }

}
