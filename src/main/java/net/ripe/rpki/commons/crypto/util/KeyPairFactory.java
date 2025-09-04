package net.ripe.rpki.commons.crypto.util;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class KeyPairFactory {

    public static final String DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    public static final String DEFAULT_EC_KEYPAIR_GENERATOR_PROVIDER = "SunEC";

    public static final String ALGORITHM = "RSA";
    private static final BigInteger RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

    static final int RPKI_RSA_KEY_PAIR_SIZE = 2048;

    public static final String ECDSA_ALGORITHM = "EC";
    public static final String ECDSA_CURVE = "secp256r1";

    private final static KeyPairGenerator rsaGenerator;
    private final static KeyPairGenerator ecGenerator;

    static {
        try {
            rsaGenerator = KeyPairGenerator.getInstance(ALGORITHM, DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER);
            rsaGenerator.initialize(new RSAKeyGenParameterSpec(RPKI_RSA_KEY_PAIR_SIZE, RSA_PUBLIC_EXPONENT));

            ecGenerator = KeyPairGenerator.getInstance(ECDSA_ALGORITHM, DEFAULT_EC_KEYPAIR_GENERATOR_PROVIDER);
            ecGenerator.initialize(new ECGenParameterSpec(ECDSA_CURVE), new SecureRandom());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public KeyPairFactory() {
    }

    public KeyPair generate() {
        return rsaGenerator.generateKeyPair();
    }

    public KeyPair generateEC() {
        return ecGenerator.generateKeyPair();
    }

    /**
     * Decodes an X.509 encoded public key.
     *
     * @param encoded the encoded public key.
     * @return the PublicKey.
     */
    public static PublicKey decodePublicKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    /**
     * Decodes a PKCS#8 encoded private key. This is the default encoding for
     * the private key getEncoded method.
     *
     * @param encoded the encoded data.
     * @return the PrivateKey.
     */
    public static PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    public static PublicKey decodePublicKeyEC(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ECDSA_ALGORITHM).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    /**
     * Decodes a PKCS#8 encoded private key. This is the default encoding for
     * the private key getEncoded method.
     *
     * @param encoded the encoded data.
     * @return the PrivateKey.
     */
    public static PrivateKey decodePrivateKeyEC(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ECDSA_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }
}
