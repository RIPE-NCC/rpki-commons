package net.ripe.rpki.commons.crypto.util;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class EcKeyPairFactory {
    public static final String ALGORITHM = "EC";

    private final String provider;

    public EcKeyPairFactory(String provider) {
        this.provider = provider;
    }

    public KeyPair generate() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, provider);
            generator.initialize(new ECGenParameterSpec("secp256r1"));
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

    public EcKeyPairFactory withProvider(String provider) {
        return new EcKeyPairFactory(provider);
    }
}
