package net.ripe.commons.certification.util;

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

public final class KeyPairFactory {

    public static final String ALGORITHM = "RSA";

    /** F4 Public Exponent */
    public static final BigInteger PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

    private KeyPairFactory() {
    }

    public static KeyPairFactory getInstance() {
        return new KeyPairFactory();
    }

    public KeyPair generate(int size, String provider) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, provider);
            generator.initialize(new RSAKeyGenParameterSpec(size, PUBLIC_EXPONENT));
            return generator.generateKeyPair();
        } catch (NoSuchProviderException e) {
            throw new KeyPairFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
        	throw new KeyPairFactoryException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    /**
     * Decodes an X.509 encoded public key.
     *
     * @param encoded the encoded public key.
     * @return the PublicKey.
     */
    public PublicKey decodePublicKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException e) {
            throw new KeyPairFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
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
    public PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException e) {
            throw new KeyPairFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }
}
