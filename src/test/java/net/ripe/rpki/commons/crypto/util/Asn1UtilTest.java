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
package net.ripe.rpki.commons.crypto.util;

import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceType;
import net.ripe.ipresource.Ipv4Address;
import net.ripe.ipresource.UniqueIpResource;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.junit.Test;

import static net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoderTest.*;
import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static org.junit.Assert.*;

public class Asn1UtilTest {

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailToParseNonZeroPadBits() {
        byte[] WRONG_ENCODED_IPV4_10_5_0_0_23 = {0x03, 0x04, 0x01, 0x0a, 0x05, 0x01};
        parseIpAddressAsPrefix(IpResourceType.IPv4, decode(WRONG_ENCODED_IPV4_10_5_0_0_23));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailIPv4ParsingWhenNoValidDerBitStringFoundP() {
        byte[] WRONG_ENCODED_IPV4_10_5_0_0_23 = {0x05, 0x04, 0x01, 0x0a, 0x05, 0x01};
        parseIpAddressAsPrefix(IpResourceType.IPv4, decode(WRONG_ENCODED_IPV4_10_5_0_0_23));
    }

    @Test
    public void shouldParseIpv4Address() {
        assertEquals(IpResource.parse("0.0.0.0/0"), parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_0_0_0_0_0)));
        assertEquals(IpResource.parse("10.5.0.4/32"), parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_5_0_4_32)));
        assertEquals(IpResource.parse("10.5.0.0/23"), parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_5_0_0_23)));
        assertEquals(IpResource.parse("10.64.0.0/12"), parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_64_0_0_12)));
        assertEquals(IpResource.parse("10.64.0.0/20"), parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_64_0_0_20)));
        assertEquals(IpResource.parse("128.5.0.4/32"), parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_128_5_0_4_32)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailToParseNonZeroPadBitsIpv4Address() {
        byte[] WRONG_ENCODED_IPV4_10_5_0_0 = {0x03, 0x03, 0x01, 0x0a, 0x05};
        parseIpAddress(IpResourceType.IPv4, decode(WRONG_ENCODED_IPV4_10_5_0_0), false);
    }

    @Test
    public void shouldParseIpv6Addresses() {
        assertEquals(IpResource.parse("2001:0:200:3::1/128"),
                parseIpAddressAsPrefix(IpResourceType.IPv6, decode(ENCODED_IPV6_2001_0_200_3_0_0_0_1_128)));
        assertEquals(IpResource.parse("2001:0:200::/39"), parseIpAddressAsPrefix(IpResourceType.IPv6, decode(ENCODED_IPV6_2001_0_200_39)));
    }

    @Test
    public void shouldEncodeIpv4Address() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_10_5_0_4_32, encodeIpAddress(IpRange.parse("10.5.0.4/32")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_128_5_0_4_32, encodeIpAddress(IpRange.parse("128.5.0.4/32")));
    }

    @Test
    public void shouldEncodeIpv4Prefix() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_0_0_0_0_0, encodeIpAddress(IpRange.parse("0.0.0.0/0")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_10_5_0_0_23, encodeIpAddress(IpRange.parse("10.5.0.0/23")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_10_64_0_0_12, encodeIpAddress(IpRange.parse("10.64.0.0/12")));
        Asn1UtilTest.assertEncoded(ENCODED_IPV4_10_64_0_0_20, encodeIpAddress(IpRange.parse("10.64.0.0/20")));
    }

    @Test
    public void shouldEncodeIpv6Address() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV6_2001_0_200_3_0_0_0_1_128, encodeIpAddress(IpRange.parse("2001:0:200:3:0:0:0:1/128")));
    }

    @Test
    public void shouldEncodeIpv6Prefix() {
        Asn1UtilTest.assertEncoded(ENCODED_IPV6_2001_0_200_39, encodeIpAddress(IpRange.parse("2001:0:200::/39")));
    }

    @Test
    public void shouldDecodeAsn() {
        assertEquals(ASN_0, parseAsId(decode(ENCODED_ASN_0)));
        assertEquals(ASN_127, parseAsId(decode(ENCODED_ASN_127)));
        assertEquals(ASN_128, parseAsId(decode(ENCODED_ASN_128)));
        assertEquals(ASN_412_233, parseAsId(decode(ENCODED_ASN_412_233)));
        assertEquals(ASN_65535_65535, parseAsId(decode(ENCODED_ASN_65535_65535)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnOutOfRangeAsn() {
        parseAsId(new ASN1Integer(-1));
    }

    @Test
    public void HandleZeroSlashEight() {
        String expected = "0.12.0.0";
        UniqueIpResource ip = Ipv4Address.parse(expected);
        int bits = 16;
        DERBitString bitString = Asn1Util.resourceToBitString(ip, bits);

        IpRange ipAfter = Asn1Util.parseIpAddressAsPrefix(IpResourceType.IPv4, bitString);
        String actual = ipAfter.toString();

        assertEquals("The ip addresses should not have mutated!", expected + "/16", actual);
    }

    public static void assertEncoded(byte[] expected, ASN1Encodable encodable) {
        byte[] actual = encode(encodable);
        assertArrayEquals(expected, actual);
    }

}
