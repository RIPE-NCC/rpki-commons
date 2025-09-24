package net.ripe.rpki.commons.crypto.util;

import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;


public class KeyPairFactoryTest {

    public static KeyPair TEST_KEY_PAIR = KeyPairFactory.rsa().generate();
    public static KeyPair SECOND_TEST_KEY_PAIR = KeyPairFactory.rsa().generate();

    public static KeyPair TEST_EC_KEY_PAIR = KeyPairFactory.bgpSec().generate();
    public static KeyPair SECOND_EC_TEST_KEY_PAIR = KeyPairFactory.bgpSec().generate();

    private static final Map<String, KeyPair> cachedKeyPairs = new HashMap<>();

    public static KeyPair getKeyPair(String name) {
        synchronized (cachedKeyPairs) {
            KeyPair result = cachedKeyPairs.get(name);
            if (result == null) {
                result = KeyPairFactory.rsa().generate();
                cachedKeyPairs.put(name, result);
            }
            return result;
        }
    }

    @Test
    public void shouldGenerateRsaKeyPairsByDefault() {
        KeyPair keyPair = new KeyPairFactory(KeyPairFactory.DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER).generate();
        assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
        assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);

        assertEquals(keyPair.getPublic(), KeyPairFactory.decodePublicKey(keyPair.getPublic().getEncoded()));
        assertEquals(keyPair.getPrivate(), KeyPairFactory.decodePrivateKey(keyPair.getPrivate().getEncoded()));

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        assertEquals("RSA", rsaPublicKey.getAlgorithm());
        assertEquals(KeyPairFactory.RPKI_RSA_KEY_PAIR_SIZE, rsaPublicKey.getModulus().bitLength());
    }

    @Test
    public void shouldGenerateBgpSecKeyPairsWhenAsked() {
        KeyPair keyPair = KeyPairFactory.bgpSec().generate();
        assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);

        assertEquals(keyPair.getPublic(), KeyPairFactory.decodePublicKeyEC(keyPair.getPublic().getEncoded()));
        assertEquals(keyPair.getPrivate(), KeyPairFactory.decodePrivateKeyEC(keyPair.getPrivate().getEncoded()));

        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        assertEquals("EC", ecPublicKey.getAlgorithm());
    }

    @Test(expected = RuntimeException.class)
    public void shouldDecodePublicKeyFailOnInvalidInput() {
        KeyPairFactory.decodePublicKey(new byte[]{0});
    }

    @Test(expected = RuntimeException.class)
    public void shouldDecodePrivateKeyFailOnInvalidInput() {
        KeyPairFactory.decodePrivateKey(new byte[]{0});
    }
}
