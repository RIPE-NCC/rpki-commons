package net.ripe.rpki.commons.crypto.util;

import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;


public class KeyPairFactoryTest {
    public static final String EC_KEYPAIR_GENERATOR_PROVIDER = "SunEC";
    public static final String RSA_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";

    public static KeyPair TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    public static KeyPair SECOND_TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    public static KeyPair EC_TEST_KEY_PAIR = PregeneratedEcKeyPairFactory.getInstance().generate();;
    public static KeyPair EC_SECOND_TEST_KEY_PAIR = PregeneratedEcKeyPairFactory.getInstance().generate();

    private static final ConcurrentHashMap<String, KeyPair> cachedKeyPairs = new ConcurrentHashMap();
    private static final ConcurrentHashMap<String, KeyPair> cachedEcKeyPairs = new ConcurrentHashMap();


    public static KeyPair getKeyPair(String name) {
        return cachedKeyPairs.computeIfAbsent(name, unused -> PregeneratedKeyPairFactory.getInstance().generate());
    }

    public static KeyPair getEcKeyPair(String name) {
        return cachedEcKeyPairs.computeIfAbsent(name, unused -> PregeneratedEcKeyPairFactory.getInstance().generate());
    }


    @Test
    public void shouldGenerateRsaKeyPairs() {
        KeyPair keyPair = new KeyPairFactory(RSA_KEYPAIR_GENERATOR_PROVIDER).generate();
        assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
        assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);

        assertEquals(keyPair.getPublic(), KeyPairFactory.decodePublicKey(keyPair.getPublic().getEncoded()));
        assertEquals(keyPair.getPrivate(), KeyPairFactory.decodePrivateKey(keyPair.getPrivate().getEncoded()));

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        assertEquals("RSA", rsaPublicKey.getAlgorithm());
        assertEquals(KeyPairFactory.RPKI_KEY_PAIR_SIZE, rsaPublicKey.getModulus().bitLength());
    }

    @Test
    public void shouldGenerateEcdsaKeyPairs() {
        KeyPair keyPair = new EcKeyPairFactory(EC_KEYPAIR_GENERATOR_PROVIDER).generate();
        assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);

        assertEquals(keyPair.getPublic(), EcKeyPairFactory.decodePublicKey(keyPair.getPublic().getEncoded()));
        assertEquals(keyPair.getPrivate(), EcKeyPairFactory.decodePrivateKey(keyPair.getPrivate().getEncoded()));

        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        assertEquals("EC", ecPublicKey.getAlgorithm());
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
