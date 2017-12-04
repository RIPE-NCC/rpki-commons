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

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.util.Asn1UtilTest;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.SortedMap;
import java.util.TreeMap;

import static org.junit.Assert.*;

//ESCA-JAVA0076:
public class ResourceExtensionEncoderTest {


    public static final Asn ASN_0 = Asn.parse("AS0");
    public static final Asn ASN_127 = Asn.parse("AS127");
    public static final Asn ASN_128 = Asn.parse("AS128");
    public static final Asn ASN_412_233 = Asn.parse("AS412.233");
    public static final Asn ASN_65535_65535 = Asn.parse("AS65535.65535");

    // Expected byte arrays for the tests:
    public static final byte[] ENCODED_NULL = {0x05, 0x00};

    // Addresses
    public static final byte[] ENCODED_IPV4_0_0_0_0_0 = {0x03, 0x01, 0x00};
    public static final byte[] ENCODED_IPV4_10_5_0_4_32 = {0x03, 0x05, 0x00, 0x0a, 0x05, 0x00, 0x04};
    public static final byte[] ENCODED_IPV4_10_5_0_0_23 = {0x03, 0x04, 0x01, 0x0a, 0x05, 0x00};
    public static final byte[] ENCODED_IPV4_128_5_0_4_32 = {0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04};

    public static final byte[] ENCODED_IPV4_10_64_0_0_12 = {0x03, 0x03, 0x04, 0x0a, 0x40};
    public static final byte[] ENCODED_IPV4_10_64_0_0_20 = {0x03, 0x04, 0x04, 0x0a, 0x40, 0x00};

    public static final byte[] ENCODED_IPV6_2001_0_200_3_0_0_0_1_128 = {0x03, 0x11, 0x00, 0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01};
    public static final byte[] ENCODED_IPV6_2001_0_200_39 = {0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02};

    // Ranges
    public static final byte[] ENCODED_IPV4_RANGE_10_5_0_0_TO_10_5_1_255 = {0x30, 0x0b, 0x03, 0x03, 0x00, 0x0a, 0x05, 0x03, 0x04, 0x01, 0x0a, 0x05, 0x00};
    public static final byte[] ENCODED_IPV4_RANGE_10_5_4_0_TO_10_5_15_255 = {0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00};
    public static final byte[] ENCODED_IPV4_RANGE_128_5_4_0_TO_128_5_15_255 = {0x30, 0x0c, 0x03, 0x04, 0x02, (byte) 0x80, 0x05, 0x04, 0x03, 0x04, 0x04, (byte) 0x80, 0x05, 0x00};
    public static final byte[] ENCODED_IPV4_RANGE_0_0_0_0_TO_255_255_255_255 = {0x30, 0x06, 0x03, 0x01, 0x00, 0x03, 0x01, 0x00};
    public static final byte[] ENCODED_IPV6_RANGE_2001_0_200__TO_2001_0_3FF_FFFF_FFFF_FFFF_FFFF_FFFF = {0x30, 0x10, 0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02, 0x03, 0x06, 0x02, 0x20, 0x01, 0x00, 0x00, 0x00};

    // Resources
    public static final byte[] ENCODED_IPV4_RESOURCES = {0x30, 0x15, 0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00, 0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04};
    public static final byte[] ENCODED_IPV4_ADDRESS_FAMILY_RESOURCES = {0x30, 0x1b, 0x04, 0x02, 0x00, 0x01, 0x30, 0x15, 0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00, 0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04};
    public static final byte[] ENCODED_IPV4_MULTICAST_ADDRESS_FAMILY_RESOURCES = {0x30, 0x1c, 0x04, 0x03, 0x00, 0x01, 0x02, 0x30, 0x15, 0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00, 0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04};

    // IP Address Blocks extension.
    public static final byte[] ENCODED_IP_ADDRESS_BLOCKS = {
            0x30, 0x2d,
            0x30, 0x1b,
            0x04, 0x02, 0x00, 0x01, // address family: IPv4
            0x30, 0x15, // sequence containing: 10.5.4.0-10.5.15.255, 128.5.0.4/32
            0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00,
            0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04,
            0x30, 0x0e,
            0x04, 0x02, 0x00, 0x02, // address family: IPv6
            0x30, 0x08, // sequence containing 2001:0:200::/39
            0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02
    };

    // IP Address Blocks extension.
    public static final byte[] ENCODED_IP_ADDRESS_BLOCKS_EXTENSION = {
            0x04, 0x2f, // DEROctet string extension wrapper
            0x30, 0x2d,
            0x30, 0x1b,
            0x04, 0x02, 0x00, 0x01, // address family: IPv4
            0x30, 0x15, // sequence containing: 10.5.4.0-10.5.15.255, 128.5.0.4/32
            0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00,
            0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04,
            0x30, 0x0e,
            0x04, 0x02, 0x00, 0x02, // address family: IPv6
            0x30, 0x08, // sequence containing 2001:0:200::/39
            0x03, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02
    };

    public static final byte[] ENCODED_IPV4_ONLY_ADDRESS_BLOCKS = {
            0x30, 0x1d,
            0x30, 0x1b,
            0x04, 0x02, 0x00, 0x01, // address family: IPv4
            0x30, 0x15, // sequence containing: 10.5.4.0-10.5.15.255, 128.5.0.4/32
            0x30, 0x0c, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x04, 0x03, 0x04, 0x04, 0x0a, 0x05, 0x00,
            0x03, 0x05, 0x00, (byte) 0x80, 0x05, 0x00, 0x04
    };

    public static final byte[] ENCODED_IPV4_ONLY_INHERITED = {
            0x04, 0x0a, // DEROctet string extension wrapper
            0x30, 0x08,
            0x30, 0x06,
            0x04, 0x02, 0x00, 0x01, // address family: IPv4
            0x05, 0x00, // inherit
    };

    public static final byte[] ENCODED_IPV4_AND_IPV6_INHERITED = {
            0x04, 0x12, // DEROctet string extension wrapper
            0x30, 0x10,
            0x30, 0x06,
            0x04, 0x02, 0x00, 0x01, // address family: IPv4
            0x05, 0x00, // inherit
            0x30, 0x06,
            0x04, 0x02, 0x00, 0x02, // address family: IPv6
            0x05, 0x00, // inherit
    };

    // ASN
    public static final byte[] ENCODED_ASN_0 = {0x02, 0x01, 0x00};
    public static final byte[] ENCODED_ASN_127 = {0x02, 0x01, 0x7f};
    public static final byte[] ENCODED_ASN_128 = {0x02, 0x02, 0x00, (byte) 0x80};
    public static final byte[] ENCODED_ASN_412_233 = {0x02, 0x04, 0x01, (byte) 0x9c, 0x00, (byte) 0xe9};
    public static final byte[] ENCODED_ASN_65535_65535 = {0x02, 0x05, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};

    public static final byte[] ENCODED_ASN_127_TO_128 = {0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, (byte) 0x80};
    public static final byte[] ENCODED_ASN_0_TO_65535_65535 = {0x30, 0x0a, 0x02, 0x01, 0x00, 0x02, 0x05, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};

    public static final byte[] ENCODED_AS_IDS_OR_RANGES = {0x30, 0x0f, 0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, (byte) 0x80, 0x02, 0x04, 0x01, (byte) 0x9c, 0x00, (byte) 0xe9};

    public static final byte[] ENCODED_AS_IDENTIFIERS = {
            0x30, 0x13, // AS identifiers
            (byte) 0xa0, 0x11, // asnum
            0x30, 0x0f, // sequence contianing AS127-128, AS412.233
            0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, (byte) 0x80,
            0x02, 0x04, 0x01, (byte) 0x9c, 0x00, (byte) 0xe9
    };

    public static final byte[] ENCODED_AS_IDENTIFIERS_EXTENSION = {
            0x04, 0x15, // Octet string extension wrapper
            0x30, 0x13, // AS identifiers
            (byte) 0xa0, 0x11, // asnum
            0x30, 0x0f, // sequence contianing AS127-128, AS412.233
            0x30, 0x07, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, (byte) 0x80,
            0x02, 0x04, 0x01, (byte) 0x9c, 0x00, (byte) 0xe9
    };

    public static final byte[] ENCODED_AS_IDENTIFIERS_INHERITED = {
            0x04, 0x06, // Octet string extension wrapper
            0x30, 0x04, // AS identifiers
            (byte) 0xa0, 0x02, // asnum
            0x05, 0x00, // inherited
    };


    public static final byte[] RFC3779_APPENDIX_B_EXAMPLE_1 = {0x30, 0x35, 0x30, 0x2b, 0x04, 0x03, 0x00, 0x01, 0x01, 0x30, 0x24, 0x03, 0x04, 0x04, 0x0a, 0x00, 0x20, 0x03, 0x04, 0x00,
            0x0a, 0x00, 0x40, 0x03, 0x03, 0x00, 0x0a, 0x01, 0x30, 0x0c, 0x03, 0x04, 0x04, 0x0a, 0x02, 0x30, 0x03, 0x04, 0x00, 0x0a, 0x02, 0x40,
            0x03, 0x03, 0x00, 0x0a, 0x03, 0x30, 0x06, 0x04, 0x02, 0x00, 0x02, 0x05, 0x00};

    public static final byte[] RFC3779_APPENDIX_B_EXAMPLE_2 = {0x30, 0x2c, 0x30, 0x10, 0x04, 0x03, 0x00, 0x01, 0x01, 0x30, 0x09, 0x03, 0x02, 0x00,
            0x0a, 0x03, 0x03, 0x04, (byte) 0xb0, 0x10, 0x30, 0x07, 0x04, 0x03, 0x00, 0x01, 0x02, 0x05, 0x00, 0x30, 0x0f, 0x04, 0x02, 0x00, 0x02,
            0x30, 0x09, 0x03, 0x07, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x02};

    public static final byte[] RFC3779_APPENDIX_C_EXAMPLE = {0x30, 0x1a, (byte) 0xa0, 0x14, 0x30, 0x12, 0x02, 0x02, 0x00, (byte) 0x87, 0x30, 0x08,
            0x02, 0x02, 0x0b, (byte) 0xb8, 0x02, 0x02, 0x0f, (byte) 0x9f, 0x02, 0x02, 0x13, (byte) 0x89, (byte) 0xa1, 0x02, 0x05, 0x00};

    private ResourceExtensionEncoder subject;

    @Before
    public void setUp() {
        subject = new ResourceExtensionEncoder();
    }

    @Test
    public void shouldEncodeIpv4Range() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_RANGE_10_5_0_0_TO_10_5_1_255, subject.ipRangeToDer(IpRange.parse("10.5.0.0-10.5.1.255")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_RANGE_10_5_4_0_TO_10_5_15_255, subject.ipRangeToDer(IpRange.parse("10.5.4.0-10.5.15.255")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_RANGE_128_5_4_0_TO_128_5_15_255, subject.ipRangeToDer(IpRange.parse("128.5.4.0-128.5.15.255")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_RANGE_0_0_0_0_TO_255_255_255_255, subject.ipRangeToDer(IpRange.parse("0.0.0.0-255.255.255.255")));
    }

    @Test
    public void shouldEncodeIpv6Range() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV6_RANGE_2001_0_200__TO_2001_0_3FF_FFFF_FFFF_FFFF_FFFF_FFFF, subject.ipRangeToDer(IpRange.parse("2001:0:200::-2001:0:3ff:ffff:ffff:ffff:ffff:ffff")));
    }

    @Test
    public void shouldEncodeIpAddressOrRange() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_10_5_0_0_23, subject.ipAddressOrRangeToDer(IpRange.parse("10.5.0.0/23")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_RANGE_10_5_4_0_TO_10_5_15_255, subject.ipAddressOrRangeToDer(IpRange.parse("10.5.4.0-10.5.15.255")));
    }

    @Test
    public void shouldEncodeIpAddressChoice() {
        IpResourceSet resources = new IpResourceSet(IpRange.parse("128.5.0.4/32"), IpRange.parse("10.5.4.0-10.5.15.255"));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_RESOURCES, subject.ipAddressChoiceToDer(IpResourceType.IPv4, resources));
        Asn1UtilTest.assertEncoded(ENCODED_NULL, subject.ipAddressChoiceToDer(IpResourceType.IPv4, null));

    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectEmptyIpAddressesOrRanges() {
        IpResourceSet resources = new IpResourceSet(IpRange.parse("128.5.0.4/30"));
        subject.ipAddressChoiceToDer(IpResourceType.IPv6, resources);
    }

    @Test
    public void shouldEncodeIpAddressFamily() {
        IpResourceSet resources = new IpResourceSet(IpRange.parse("128.5.0.4/32"), IpRange.parse("10.5.4.0-10.5.15.255"));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_ADDRESS_FAMILY_RESOURCES, subject.ipAddressFamilyToDer(AddressFamily.IPV4, resources));
    }

    @Test
    public void shouldEncodeIpAddressFamilyWithSafi() {
        IpResourceSet resources = new IpResourceSet(IpRange.parse("128.5.0.4/32"), IpRange.parse("10.5.4.0-10.5.15.255"));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_MULTICAST_ADDRESS_FAMILY_RESOURCES, subject.ipAddressFamilyToDer(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(2), resources));

    }

    @Test
    public void shouldEncodeIpAddressBlocks() throws IOException {
        IpResourceSet resources = new IpResourceSet(IpRange.parse("128.5.0.4/32"), IpRange.parse("10.5.4.0-10.5.15.255"), IpRange.parse("2001:0:200::-2001:0:3ff:ffff:ffff:ffff:ffff:ffff"));
        assertArrayEquals(ENCODED_IP_ADDRESS_BLOCKS, subject.encodeIpAddressBlocks(false, false, resources).getEncoded());

        resources = new IpResourceSet(IpRange.parse("128.5.0.4/32"), IpRange.parse("10.5.4.0-10.5.15.255"));
        assertArrayEquals(ENCODED_IPV4_ONLY_ADDRESS_BLOCKS, subject.encodeIpAddressBlocks(false, false, resources).getEncoded());
    }

    @Test
    public void shouldNotEncodeEmptyIpAddressBlocksExtension() {
        assertNull(subject.encodeIpAddressBlocks(false, false, new IpResourceSet()));
    }

    @Test
    public void shouldEncodeAsn() {
        Asn1UtilTest.assertEncoded(ENCODED_ASN_0, subject.asIdToDer(ASN_0));
        Asn1UtilTest.assertEncoded(ENCODED_ASN_127, subject.asIdToDer(ASN_127));
        Asn1UtilTest.assertEncoded(ENCODED_ASN_128, subject.asIdToDer(ASN_128));
        Asn1UtilTest.assertEncoded(ENCODED_ASN_412_233, subject.asIdToDer(ASN_412_233));
        Asn1UtilTest.assertEncoded(ENCODED_ASN_65535_65535, subject.asIdToDer(ASN_65535_65535));
    }

    @Test
    public void shouldEncodeAsRange() {
        Asn1UtilTest.assertEncoded(ENCODED_ASN_127_TO_128, subject.asRangeToDer(ASN_127.upTo(ASN_128)));
        Asn1UtilTest.assertEncoded(ENCODED_ASN_0_TO_65535_65535, subject.asRangeToDer(ASN_0.upTo(ASN_65535_65535)));
    }

    @Test
    public void shouldEncodeAsIdOrRange() {
        Asn1UtilTest.assertEncoded(ENCODED_ASN_127, subject.asIdOrRangeToDer(ASN_127.upTo(ASN_127)));
        Asn1UtilTest.assertEncoded(ENCODED_ASN_127_TO_128, subject.asIdOrRangeToDer(ASN_127.upTo(ASN_128)));
    }

    @Test
    public void shouldEncodeAsIdsOrRanges() {
        IpResourceSet resources = new IpResourceSet(ASN_412_233, ASN_127.upTo(ASN_128));
        Asn1UtilTest.assertEncoded(ENCODED_AS_IDS_OR_RANGES, subject.asIdsOrRangesToDer(resources));
    }

    @Test
    public void shouldEncodeAsIdentifierChoice() {
        IpResourceSet resources = new IpResourceSet(ASN_412_233, ASN_127.upTo(ASN_128));
        Asn1UtilTest.assertEncoded(ENCODED_NULL, subject.asIdentifierChoiceToDer(true, resources));
        Asn1UtilTest.assertEncoded(ENCODED_AS_IDS_OR_RANGES, subject.asIdentifierChoiceToDer(false, resources));
    }

    @Test
    public void shouldEncodeAsIdentifiers() throws IOException {
        IpResourceSet resources = new IpResourceSet(ASN_412_233, ASN_127.upTo(ASN_128));
        assertArrayEquals(ENCODED_AS_IDENTIFIERS, subject.encodeAsIdentifiers(false, resources).getEncoded());
    }

    @Test
    public void shouldNotEncodeEmptyAsIdentifiersExtension() {
        assertNull(subject.encodeAsIdentifiers(false, IpResourceSet.parse("10.0.0.0/8")));
    }

    /**
     * The first example in Appendix B of RFC3779.
     */
    @Test
    public void shouldEncodeRfc3779AppendixBFirstExample() {
        SortedMap<AddressFamily, IpResourceSet> resources = new TreeMap<AddressFamily, IpResourceSet>();
        resources.put(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(1),
                IpResourceSet.parse("10.0.32.0/20, 10.0.64.0/24, 10.1.0.0/16, 10.2.48.0/20, 10.2.64.0/24, 10.3.0.0/16"));
        resources.put(AddressFamily.IPV6, null);
        Asn1UtilTest.assertEncoded(RFC3779_APPENDIX_B_EXAMPLE_1, subject.ipAddressBlocksToDer(resources));
    }

    /**
     * The first example in Appendix B of RFC3779. Note that the example lists
     * 172.16/12, which is incorrect (the encoded example is 176.12/12, 0xb0
     * instead of 0xac).
     */
    @Test
    public void shouldEncodeRfc3779AppendixBSecondExample() {
        SortedMap<AddressFamily, IpResourceSet> resources = new TreeMap<AddressFamily, IpResourceSet>();
        resources.put(AddressFamily.IPV6, IpResourceSet.parse("2001:0:2::/48"));
        resources.put(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(1),
                IpResourceSet.parse("10.0.0.0/8,176.16.0.0/12"));
        resources.put(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(2), null);
        Asn1UtilTest.assertEncoded(RFC3779_APPENDIX_B_EXAMPLE_2, subject.ipAddressBlocksToDer(resources));
    }

    /**
     * The example in Appendix C of RFC3779.
     */
    @Test
    public void shouldEncodeRfc3779AppendixCExample() {
        IpResourceSet asnResources = IpResourceSet.parse("AS135, AS3000-AS3999, AS5001");
        Asn1UtilTest.assertEncoded(RFC3779_APPENDIX_C_EXAMPLE, subject.asIdentifiersToDer(false, asnResources, true, null));
    }

}
