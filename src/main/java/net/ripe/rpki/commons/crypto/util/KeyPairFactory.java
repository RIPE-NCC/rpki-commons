package net.ripe.rpki.commons.crypto.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyPairFactory {

    public static final String ALGORITHM = "RSA";

    static final int RPKI_KEY_PAIR_SIZE = 2048;

    /**
     * F4 Public Exponent
     */
    private static final BigInteger PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

    private final String provider;

    public KeyPairFactory(String provider) {
        this.provider = provider;
    }

    public KeyPair generate() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, provider);
            generator.initialize(new RSAKeyGenParameterSpec(RPKI_KEY_PAIR_SIZE, PUBLIC_EXPONENT));
            return generator.generateKeyPair();
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new KeyPairFactoryException(e);
        }
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

    public KeyPairFactory withProvider(String provider) {
        return new KeyPairFactory(provider);
    }
}
