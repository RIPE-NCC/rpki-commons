package net.ripe.rpki.commons.crypto.util;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpAddress;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceType;
import net.ripe.ipresource.UniqueIpResource;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public final class Asn1Util {

    private Asn1Util() {
        // Utility classes should not have a public or default constructor.
    }

    public static byte[] encode(ASN1Encodable value) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ASN1OutputStream derOutputStream = ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER);
            derOutputStream.writeObject(value);
            derOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new Asn1UtilException("IO exception while encoding resource extension", e);
        }
    }

    public static DERBitString resourceToBitString(UniqueIpResource resource, int bitCount) {
        int resourceTypeByteSize = resource.getType().getBitSize() / Byte.SIZE;

        byte[] value = resource.getValue().toByteArray();
        byte[] padded;
        if (value.length > resourceTypeByteSize) {
            // Skip extra sign byte added by BigInteger.
            padded = Arrays.copyOfRange(value, 1, value.length);
        } else if (value.length < resourceTypeByteSize) {
            // Pad with leading zero bytes (e.g. 0.12.0.0)
            padded = new byte[resourceTypeByteSize];
            System.arraycopy(value, 0, padded, resourceTypeByteSize - value.length, value.length);
        } else {
            padded = value;
        }

        assert padded.length == resourceTypeByteSize : "incorrect padded length";

        int byteCount = (bitCount + Byte.SIZE - 1) / Byte.SIZE;
        int unusedBits = Byte.SIZE - 1 - ((bitCount + Byte.SIZE - 1) % Byte.SIZE);
        return new DERBitString(ArrayUtils.subarray(padded, 0, byteCount), unusedBits);
    }

    /**
     * Decodes the byte array extension using the {@link ASN1InputStream}.
     */
    public static ASN1Primitive decode(byte[] extension) {
        try {
            ASN1InputStream is = new ASN1InputStream(extension);
            return is.readObject();
        } catch (IOException e) {
            throw new Asn1UtilException("IO exception while decoding resource extension", e);
        }
    }

    /**
     * Checks if <code>value</code> is an instance of the
     * <code>expectedClass</code>.
     *
     * @throws IllegalArgumentException the instance is null or not an instance of the expected
     *                                  class.
     */
    public static <T extends ASN1Encodable> T expect(ASN1Encodable value, Class<? extends T> expectedClass) {
        if (value != null) {
            try {
                return expectedClass.cast(value);
            } catch (ClassCastException e) {
                throw new IllegalArgumentException(
                        expectedClass.getSimpleName() + " expected, got " + value.getClass().getSimpleName() +
                                " with value: " + value
                );
            }
        } else {
            throw new IllegalArgumentException(expectedClass.getSimpleName() + " expected, got null");
        }
    }

    /**
     * {@link IpAddress} used as a prefix.
     */
    public static IpRange parseIpAddressAsPrefix(IpResourceType type, ASN1Encodable der) {
        expect(der, DERBitString.class);
        DERBitString derBitString = (DERBitString) der;

        IpAddress ipAddress = parseIpAddress(type, derBitString, false);

        int padBits = derBitString.getPadBits();
        return IpRange.prefix(ipAddress, derBitString.getBytes().length * Byte.SIZE - padBits);
    }

    /**
     * IPAddress ::= BIT STRING
     */
    public static IpAddress parseIpAddress(IpResourceType type, ASN1Encodable der, boolean padWithOnes) {
        expect(der, DERBitString.class);
        DERBitString derBitString = (DERBitString) der;

        byte[] bytes = derBitString.getBytes();
        BigInteger value = new BigInteger(1, bytes);
        int usedBits = bytes.length * Byte.SIZE;
        int neededBits = type.getBitSize();
        int padBits = derBitString.getPadBits();

        if (padBits > 0) {
            byte lastByte = bytes[bytes.length - 1];
            byte mask = (byte) ((1 << padBits) - 1);
            Validate.isTrue((lastByte & mask) == 0, "pad bits not zero");
        }

        BigInteger upperBits = value.shiftLeft(neededBits - usedBits);
        BigInteger lowerBits = BigInteger.ZERO;
        if (padWithOnes) {
            lowerBits = BigInteger.ONE.shiftLeft(neededBits - usedBits + padBits).subtract(BigInteger.ONE);
        }

        return (IpAddress) type.fromBigInteger(upperBits.or(lowerBits));
    }

    /**
     * ASId ::= INTEGER
     *
     * @ensures ASId is a valid 32-bit ASN
     * @throws IllegalArgumentException when the wrong encoding is used or value is not a valid 32-bit ASN.
     */
    public static Asn parseAsId(ASN1Encodable der) {
        return new Asn(expect(der, ASN1Integer.class).getValue());
    }

    /**
     * IPAddress ::= BIT STRING
     */
    public static DERBitString encodeIpAddress(IpRange prefix) {
        Validate.isTrue(prefix.isLegalPrefix(), "not a legal prefix: " + prefix);
        return resourceToBitString(prefix.getStart(), prefix.getPrefixLength());
    }
}
