package net.ripe.rpki.commons.crypto.rfc3779;

import lombok.Value;
import net.ripe.ipresource.IpResourceType;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;

import java.io.Serializable;
import java.util.Objects;

/**
 * See {@link http://www.ietf.org/rfc/rfc3779.txt},
 * {@link http://www.iana.org/assignments/address-family-numbers} and
 * {@link http://www.iana.org/assignments/safi-namespace}.
 */
@Value
public class AddressFamily implements Comparable<AddressFamily>, Serializable {
    private static final long serialVersionUID = 1L;

    private static final int BYTE_MASK = 0xff;

    private static final int AFI_MIN = 0;
    private static final int AFI_MAX = 65535;

    private static final int SAFI_MIN = 0;
    private static final int SAFI_MAX = 255;

    private static final int AFI_IPV4 = 1;
    private static final int AFI_IPV6 = 2;

    public static final AddressFamily IPV4 = new AddressFamily(AFI_IPV4);
    public static final AddressFamily IPV6 = new AddressFamily(AFI_IPV6);

    private static final int AFI_OCTET_COUNT_WITHOUT_SAFI = 2;
    private static final int AFI_OCTET_COUNT_WITH_SAFI = 3;

    private int addressFamilyIdentifier;
    private Integer subsequentAddressFamilyIdentifier;

    public AddressFamily(int addressFamilyIdentifier) {
        this(addressFamilyIdentifier, null);
    }

    public AddressFamily(int addressFamilyIdentifier, Integer subsequentAddressFamilyIdentifier) {
        Validate.isTrue(addressFamilyIdentifier >= AFI_MIN && addressFamilyIdentifier <= AFI_MAX, "addressFamilyIdentifier out of bounds: "
                + addressFamilyIdentifier);
        Validate.isTrue(subsequentAddressFamilyIdentifier == null
                || (subsequentAddressFamilyIdentifier >= SAFI_MIN && subsequentAddressFamilyIdentifier <= SAFI_MAX),
                "subsequentAddressFamilyIdentifier out of bounds: " + subsequentAddressFamilyIdentifier);
        this.addressFamilyIdentifier = addressFamilyIdentifier;
        this.subsequentAddressFamilyIdentifier = subsequentAddressFamilyIdentifier;
    }

    public AddressFamily withoutSubsequentAddressFamilyIdentifier() {
        return new AddressFamily(getAddressFamilyIdentifier());
    }

    public AddressFamily withSubsequentAddressFamilyIdentifier(Integer subsequentAddressFamilyIdentifier) {
        return new AddressFamily(getAddressFamilyIdentifier(), subsequentAddressFamilyIdentifier);
    }

    public boolean hasSubsequentAddressFamilyIdentifier() {
        return subsequentAddressFamilyIdentifier != null;
    }

    @Override
    public int compareTo(AddressFamily that) {
        int rc = this.getAddressFamilyIdentifier() - that.getAddressFamilyIdentifier();
        if (rc != 0) {
            return rc;
        }
        if (Objects.equals(this.getSubsequentAddressFamilyIdentifier(), that.getSubsequentAddressFamilyIdentifier())) {
            return 0;
        } else if (this.getSubsequentAddressFamilyIdentifier() == null) {
            return -1;
        } else if (that.getSubsequentAddressFamilyIdentifier() == null) {
            return 1;
        } else {
            return this.getSubsequentAddressFamilyIdentifier() - that.getSubsequentAddressFamilyIdentifier();
        }
    }

    public DEROctetString toDer() {
        int length = hasSubsequentAddressFamilyIdentifier() ? AFI_OCTET_COUNT_WITH_SAFI : AFI_OCTET_COUNT_WITHOUT_SAFI;

        byte[] encoded = new byte[length];
        encoded[0] = (byte) (addressFamilyIdentifier >> Byte.SIZE);
        encoded[1] = (byte) (addressFamilyIdentifier);
        if (hasSubsequentAddressFamilyIdentifier()) {
            encoded[2] = subsequentAddressFamilyIdentifier.byteValue();
        }

        return new DEROctetString(encoded);
    }

    public static AddressFamily fromDer(ASN1Encodable der) {
        Validate.isTrue(der instanceof DEROctetString, "DEROctetString expected");
        DEROctetString derOctetString = (DEROctetString) der;

        byte[] bytes = derOctetString.getOctets();

        Validate.isTrue(bytes.length == AFI_OCTET_COUNT_WITHOUT_SAFI || bytes.length == AFI_OCTET_COUNT_WITH_SAFI, "Byte array must consist of "
                + AFI_OCTET_COUNT_WITHOUT_SAFI + " or " + AFI_OCTET_COUNT_WITH_SAFI + " elements");

        int thisAddressFamilyIdentifier = (unsignedByteToInt(bytes[0]) << Byte.SIZE) | unsignedByteToInt(bytes[1]);

        AddressFamily addressFamily;
        if (bytes.length == 2) {
            addressFamily = new AddressFamily(thisAddressFamilyIdentifier);
        } else {
            // subsequentAddressIdentifier given
            int thisSafi = unsignedByteToInt(bytes[2]);
            addressFamily = new AddressFamily(thisAddressFamilyIdentifier, thisSafi);
        }
        return addressFamily;
    }

    private static int unsignedByteToInt(byte b) {
        return b & BYTE_MASK;
    }

    public static AddressFamily fromIpResourceType(IpResourceType type) {
        switch (type) {
            case IPv4:
                return IPV4;
            case IPv6:
                return IPV6;
            default:
                throw new IllegalArgumentException("no address family for type: " + type);
        }
    }

    public IpResourceType toIpResourceType() {
        switch (addressFamilyIdentifier) {
            case AFI_IPV4:
                return IpResourceType.IPv4;
            case AFI_IPV6:
                return IpResourceType.IPv6;
            default:
                throw new IllegalStateException("no IP resource type for AFI: " + addressFamilyIdentifier);
        }
    }

}
