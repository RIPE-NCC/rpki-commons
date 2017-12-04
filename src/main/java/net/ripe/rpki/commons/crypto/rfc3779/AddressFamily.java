/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.crypto.rfc3779;

import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;

import java.io.Serializable;

/**
 * See {@link http://www.ietf.org/rfc/rfc3779.txt},
 * {@link http://www.iana.org/assignments/address-family-numbers} and
 * {@link http://www.iana.org/assignments/safi-namespace}.
 */
public class AddressFamily extends EqualsSupport implements Comparable<AddressFamily>, Serializable {
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

    public int getAddressFamilyIdentifier() {
        return addressFamilyIdentifier;
    }

    public Integer getSubsequentAddressFamilyIdentifier() {
        return subsequentAddressFamilyIdentifier;
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
        if (this.getSubsequentAddressFamilyIdentifier() == that.getSubsequentAddressFamilyIdentifier()) {
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
