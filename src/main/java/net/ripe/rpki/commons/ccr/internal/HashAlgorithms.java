package net.ripe.rpki.commons.ccr.internal;

import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1Primitive;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Provides static access to the sha256 hash algorithm.
 *
 * <p>
 * When a system does not have the sha256 hashing function, this class fails to load.
 * </p>
 */
@UtilityClass
public class HashAlgorithms {
    private static final MessageDigest sha256;

    static {
        try {
            sha256 = MessageDigest.getInstance("sha256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("System does not support the 'sha256' digest algorithm.", e);
        }
    }

    /**
     * Produces the digest of given ASN.1 data.
     *
     * <p>
     * For convenience the declared {@link java.io.IOException} from {@link ASN1Primitive#getEncoded()} is captured, as
     * for in-memory ASN.1 data this exception can never occur.
     * </p>
     */
    public static byte[] digest(String algorithm, Provider provider, ASN1Primitive asn1) {
        try {
            var hash = MessageDigest.getInstance(algorithm, provider);
            return hash.digest(asn1.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("failed to clone digest algorithm", e);
        } catch (IOException e) {
            throw new IllegalStateException("failed read in-memory encoded DER data", e);
        }
    }

    /**
     * Produces the sha256 digest of given ASN.1 data.
     *
     * @see #digest(String, Provider, ASN1Primitive)
     */
    public static byte[] sha256Digest(ASN1Primitive asn1) {
        return digest(sha256.getAlgorithm(), sha256.getProvider(), asn1);
    }
}
