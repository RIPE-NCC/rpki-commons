package net.ripe.rpki.commons.crypto.util;

import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;


public class KeyPairFactoryTest {

    public static final String DEFAULT_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";

    public static final KeyPair TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    public static final KeyPair SECOND_TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    private static final Map<String, KeyPair> cachedKeyPairs = new HashMap<>();


    public static KeyPair getKeyPair(String name) {
        synchronized (cachedKeyPairs) {
            KeyPair result = cachedKeyPairs.get(name);
            if (result == null) {
                result = PregeneratedKeyPairFactory.getInstance().generate();
                cachedKeyPairs.put(name, result);
            }
            return result;
        }
    }


    @Test
    public void shouldGenerateRsaKeyPairs() {
        KeyPair keyPair = new KeyPairFactory(DEFAULT_KEYPAIR_GENERATOR_PROVIDER).generate();
        assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
        assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);

        assertEquals(keyPair.getPublic(), KeyPairFactory.decodePublicKey(keyPair.getPublic().getEncoded()));
        assertEquals(keyPair.getPrivate(), KeyPairFactory.decodePrivateKey(keyPair.getPrivate().getEncoded()));

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        assertEquals("RSA", rsaPublicKey.getAlgorithm());
        assertEquals(KeyPairFactory.RPKI_KEY_PAIR_SIZE, rsaPublicKey.getModulus().bitLength());
    }

    @Test(expected = RuntimeException.class)
    public void shouldKeypairGenerationFailOnInvalidProvider() {
        new KeyPairFactory("invalid_provider").generate();
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
