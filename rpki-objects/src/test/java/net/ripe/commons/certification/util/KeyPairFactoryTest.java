package net.ripe.commons.certification.util;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import net.ripe.commons.certification.util.KeyPairFactory;

import org.junit.Test;


public class KeyPairFactoryTest {

    public static final String DEFAULT_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";

    public static KeyPair TEST_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);
    public static KeyPair SECOND_TEST_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    private static final Map<String, KeyPair> cachedKeyPairs = new HashMap<String, KeyPair>();


    public static KeyPair getKeyPair(String name) {
        synchronized (cachedKeyPairs) {
            KeyPair result = cachedKeyPairs.get(name);
            if (result == null) {
                result = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);
                cachedKeyPairs.put(name, result);
            }
            return result;
        }
    }


    @Test
    public void shouldGenerateRsaKeyPairs() {
        KeyPair keyPair = TEST_KEY_PAIR;
        assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
        assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);

        assertEquals(keyPair.getPublic(), KeyPairFactory.getInstance().decodePublicKey(keyPair.getPublic().getEncoded()));
        assertEquals(keyPair.getPrivate(), KeyPairFactory.getInstance().decodePrivateKey(keyPair.getPrivate().getEncoded()));
    }

    @Test(expected=RuntimeException.class)
    public void shouldKeypairGenerationFailOnInvalidProvider() {
        KeyPairFactory.getInstance().generate(512, "foo provider");
    }

    @Test(expected=RuntimeException.class)
    public void shouldDecodePublicKeyFailOnInvalidInput() {
        KeyPairFactory.getInstance().decodePublicKey(new byte[] {0});
    }

    @Test(expected=RuntimeException.class)
    public void shouldDecodePrivateKeyFailOnInvalidInput() {
        KeyPairFactory.getInstance().decodePrivateKey(new byte[] {0});
    }
}
