package net.ripe.rpki.commons.crypto.util;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class KeyPairFactory {

    public static final String DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    public static final String DEFAULT_EC_KEYPAIR_GENERATOR_PROVIDER = "SunEC";

    public static final String RSA_ALGORITHM = "RSA";
    public static final String ALGORITHM = RSA_ALGORITHM;
    private static final BigInteger RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

    static final int RPKI_RSA_KEY_PAIR_SIZE = 2048;

    public static final String ECDSA_ALGORITHM = "EC";
    public static final String ECDSA_CURVE = "secp256r1";

    protected final String provider;

    public static KeyPairGenerator getEcGenerator(String provider) {
        try {
            var gen = KeyPairGenerator.getInstance(ECDSA_ALGORITHM, provider);
            gen.initialize(new ECGenParameterSpec(ECDSA_CURVE), new SecureRandom());
            return gen;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPairGenerator getRsaGenerator(String provider) {
        try {
            var gen = KeyPairGenerator.getInstance(RSA_ALGORITHM, provider);
            gen.initialize(new RSAKeyGenParameterSpec(RPKI_RSA_KEY_PAIR_SIZE, RSA_PUBLIC_EXPONENT));
            return gen;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public KeyPairFactory(String provider) {
        this.provider = provider;
    }

    public KeyPair generate() {
        return getRsaGenerator(provider).generateKeyPair();
    }

    public KeyPair generateEC() {
        return getEcGenerator(provider).generateKeyPair();
    }

    public static PublicKey decodePublicKey(byte[] encoded) {
        return decodeX509PublicKey(RSA_ALGORITHM, encoded);
    }

    public static PublicKey decodePublicKeyEC(byte[] encoded) {
        return decodeX509PublicKey(ECDSA_ALGORITHM, encoded);
    }

    public static PrivateKey decodePrivateKey(byte[] encoded) {
        return decodePKCS8PrivateKey(RSA_ALGORITHM, encoded);
    }

    public static PrivateKey decodePrivateKeyEC(byte[] encoded) {
        return decodePKCS8PrivateKey(ECDSA_ALGORITHM, encoded);
    }

    private static PublicKey decodeX509PublicKey(String rsaAlgorithm, byte[] encoded) {
        try {
            return KeyFactory.getInstance(rsaAlgorithm).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    private static PrivateKey decodePKCS8PrivateKey(String rsaAlgorithm, byte[] encoded) {
        try {
            return KeyFactory.getInstance(rsaAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    public static KeyPairFactory withProvider(String provider) {
        return new KeyPairFactory(provider);
    }
}
