package net.ripe.commons.certification.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.HexEncoder;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;


public final class KeyPairUtil {

    private KeyPairUtil() {
        // Utility classes should not have a public or default constructor.
    }

    /**
     * Get Base64 encoded public key as string. Primarily for generating filenames and transferring
     * public keys across the wire.. Not fit for decoding: strips the trailing '=' characters!
     */
    public static String getEncodedKeyIdentifier(PublicKey key) {
        String encoded = base64UrlEncode(getKeyIdentifier(key));
        return StringUtils.stripEnd(encoded, "="); // No need to decode, so we can strip padding.
    }

    /**
     * Get ASCII Hex encoded hash of the public key; for use in certificate subjects as described
     * here: http://tools.ietf.org/html/draft-ietf-sidr-res-certs-21#section-8
     */
    public static String getAsciiHexEncodedPublicKeyHash(PublicKey publicKey) {
        return hexEncodeHashData(getKeyIdentifier(publicKey));
    }

    static String hexEncodeHashData(byte[] keyHashData) {
        HexEncoder hexEncoder = new HexEncoder();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            hexEncoder.encode(keyHashData, 0, keyHashData.length, out);
            out.flush();
            return out.toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Exception hex encoding data", e);
        }
    }

    public static byte[] getKeyIdentifier(PublicKey key) {
        try {
            return new SubjectKeyIdentifierStructure(key).getKeyIdentifier();
        } catch (CertificateParsingException e) {
            throw new IllegalArgumentException("Could not get SubjectKeyIdentifierStructure from key", e);
        }
    }

    public static String base64UrlEncode(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            new FileSystemSafeBase64UrlEncoder().encode(data, 0, data.length, out);
            out.flush();
            return out.toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Exception when base64url encoding data", e);
        }
    }

    /**
     * @see <a href="http://tools.ietf.org/html/rfc4648#section-5">Base 64 Encoding with URL and
     *      Filename Safe Alphabet</a>
     */
    public static class FileSystemSafeBase64UrlEncoder extends Base64Encoder {

        public FileSystemSafeBase64UrlEncoder() {
            encodingTable[encodingTable.length - 2] = (byte) '-';
            encodingTable[encodingTable.length - 1] = (byte) '_';
            initialiseDecodingTable();
        }
    }
}
