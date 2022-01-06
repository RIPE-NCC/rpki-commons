package net.ripe.rpki.commons.crypto.util;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public final class KeyPairUtil {

    private KeyPairUtil() {
        // Utility classes should not have a public or default constructor.
    }

    /**
     * Get Base64 encoded public key as string. Primarily for generating
     * filenames and transferring public keys across the wire. Strips the trailing
     * '=' characters, which some decoders may not like!
     */
    public static String getEncodedKeyIdentifier(PublicKey key) {
        String encoded = base64UrlEncode(getKeyIdentifier(key));
        return StringUtils.stripEnd(encoded, "="); // No need to decode, so we can strip padding.
    }

    /**
     * Get ASCII Hex encoded hash of the public key; for use in certificate
     * subjects as described here:
     * https://datatracker.ietf.org/doc/html/rfc6487#section-8
     */
    public static String getAsciiHexEncodedPublicKeyHash(PublicKey publicKey) {
        return hexEncodeHashData(getKeyIdentifier(publicKey));
    }

    static String hexEncodeHashData(byte[] keyHashData) {
        return Hex.toHexString(keyHashData);
    }

    public static byte[] getKeyIdentifier(PublicKey key) {
        try {
            return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(key).getKeyIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Could not get SubjectKeyIdentifierStructure from key", e);
        }
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

}
