package net.ripe.commons.certification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpAddress;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceType;
import net.ripe.ipresource.UniqueIpResource;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROutputStream;

public final class Asn1Util {

    private Asn1Util() {
        //Utility classes should not have a public or default constructor.
    }

    public static byte[] encode(ASN1Encodable value) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DEROutputStream derOutputStream = new DEROutputStream(byteArrayOutputStream);
            derOutputStream.writeObject(value);
            derOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new Asn1UtilException("IO exception while encoding resource extension", e);
        }
    }

    public static DERBitString resourceToBitString(UniqueIpResource resource, int bitCount) {
        byte[] data = resource.getValue().toByteArray();
        int startByte = 0;
        if (data.length > resource.getType().getBitSize() / Byte.SIZE) {
            // Ignore sign byte.
            startByte = 1;
        }
        int byteCount = (bitCount + Byte.SIZE - 1) / Byte.SIZE;
        int unusedBits = Byte.SIZE - 1 - ((bitCount + Byte.SIZE - 1) % Byte.SIZE);
        return new DERBitString(ArrayUtils.subarray(data, startByte, startByte + byteCount), unusedBits);
    }

    /**
     * Decodes the byte array extension using the {@link ASN1InputStream}.
     */
    public static DERObject decode(byte[] extension) {
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
     * @throws IllegalArgumentException
     *             the instance is null or not an instance of the expected
     *             class.
     */
    public static <T extends DEREncodable> T expect(DEREncodable value, Class<? extends T> expectedClass) {
        Validate.notNull(value, expectedClass.getSimpleName() + " expected, got null");
        Validate.isTrue(expectedClass.isInstance(value), expectedClass.getSimpleName() + " expected, got " + value.getClass().getSimpleName() + " with value: " + value);
        return expectedClass.cast(value);
    }

    /**
     * {@link IpAddress} used as a prefix.
     */
    public static IpRange parseIpAddressAsPrefix(IpResourceType type, DEREncodable der) {
        expect(der, DERBitString.class);
        DERBitString derBitString = (DERBitString) der;

        IpAddress ipAddress = parseIpAddress(type, derBitString, false);

        int padBits = derBitString.getPadBits();
        return IpRange.prefix(ipAddress, derBitString.getBytes().length * Byte.SIZE - padBits);
    }

    /**
     * IPAddress ::= BIT STRING
     */
    public static IpAddress parseIpAddress(IpResourceType type, DEREncodable der, boolean padWithOnes) {
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
     */
    public static Asn parseAsId(DEREncodable der) {
        expect(der, DERInteger.class);
        return new Asn(((DERInteger) der).getValue().longValue());
    }

    /**
     * IPAddress ::= BIT STRING
     */
    public static DERBitString encodeIpAddress(IpRange prefix) {
        Validate.isTrue(prefix.isLegalPrefix(), "not a legal prefix: " + prefix);
        return resourceToBitString(prefix.getStart(), prefix.getPrefixLength());
    }
}
