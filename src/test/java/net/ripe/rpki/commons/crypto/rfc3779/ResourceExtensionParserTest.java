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

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import org.bouncycastle.asn1.ASN1Integer;
import org.junit.Before;
import org.junit.Test;

import java.util.SortedMap;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoderTest.*;
import static org.junit.Assert.*;


//ESCA-JAVA0076:
public class ResourceExtensionParserTest {

    ResourceExtensionParser parser;

    @Before
    public void setUp() {
        parser = new ResourceExtensionParser();
    }

    @Test
    public void shouldParseIpv4Range() {
        assertEquals(IpResource.parse("10.5.0.0-10.5.1.255"), parser.derToIpRange(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_RANGE_10_5_0_0_TO_10_5_1_255)));
        assertEquals(IpResource.parse("0.0.0.0-255.255.255.255"), parser.derToIpRange(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_RANGE_0_0_0_0_TO_255_255_255_255)));
        assertEquals(IpResource.parse("10.5.4.0-10.5.15.255"), parser.derToIpRange(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_RANGE_10_5_4_0_TO_10_5_15_255)));
        assertEquals(IpResource.parse("128.5.4.0-128.5.15.255"), parser.derToIpRange(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_RANGE_128_5_4_0_TO_128_5_15_255)));
    }

    @Test
    public void shouldParseIpv6Range() {
        assertEquals(IpResource.parse("2001:0:200::-2001:0:3ff:ffff:ffff:ffff:ffff:ffff"), parser.derToIpRange(IpResourceType.IPv6, Asn1Util.decode(ENCODED_IPV6_RANGE_2001_0_200__TO_2001_0_3FF_FFFF_FFFF_FFFF_FFFF_FFFF)));
    }

    @Test
    public void shouldParseIpv4AddressOrRange() {
        assertEquals(IpResource.parse("10.5.0.0-10.5.1.255"), parser.derToIpAddressOrRange(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_RANGE_10_5_0_0_TO_10_5_1_255)));
        assertEquals(IpResource.parse("0.0.0.0/0"), parser.derToIpAddressOrRange(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_0_0_0_0_0)));
    }

    @Test
    public void shouldParseIpv6AddressOrRange() {
        assertEquals(IpResource.parse("2001:0:200::-2001:0:3ff:ffff:ffff:ffff:ffff:ffff"), parser.derToIpAddressOrRange(IpResourceType.IPv6, Asn1Util.decode(ENCODED_IPV6_RANGE_2001_0_200__TO_2001_0_3FF_FFFF_FFFF_FFFF_FFFF_FFFF)));
        assertEquals(IpResource.parse("2001:0:200::/39"), parser.derToIpAddressOrRange(IpResourceType.IPv6, Asn1Util.decode(ENCODED_IPV6_2001_0_200_39)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnIllegalIpAddressOrRange() {
        parser.derToIpAddressOrRange(IpResourceType.IPv4, new ASN1Integer(123));
    }

    @Test
    public void shouldParseIpv4AddressChoice() {
        IpResourceSet ipResourceSet = new IpResourceSet();
        ipResourceSet.add(IpResource.parse("10.5.4.0-10.5.15.255"));
        ipResourceSet.add(IpResource.parse("128.5.0.4/32"));
        assertEquals(ipResourceSet, parser.derToIpAddressChoice(IpResourceType.IPv4, Asn1Util.decode(ENCODED_IPV4_RESOURCES)));
    }

    @Test
    public void shouldParseNullAsIpv4AddressChoice() {
        assertNull(parser.derToIpAddressChoice(IpResourceType.IPv4, Asn1Util.decode(ENCODED_NULL)));
    }


    @Test
    public void shouldParseIpAddressFamily() {
        IpResourceSet ipResourceSet = new IpResourceSet();
        ipResourceSet.add(IpResource.parse("10.5.4.0-10.5.15.255"));
        ipResourceSet.add(IpResource.parse("128.5.0.4/32"));

        SortedMap<AddressFamily, IpResourceSet> map = new TreeMap<AddressFamily, IpResourceSet>();
        SortedMap<AddressFamily, IpResourceSet> map2 = new TreeMap<AddressFamily, IpResourceSet>();

        map.put(AddressFamily.IPV4, ipResourceSet);
        parser.derToIpAddressFamily(Asn1Util.decode(ENCODED_IPV4_ADDRESS_FAMILY_RESOURCES), map2);

        assertEquals(map, map2);
    }

    /**
     * The first example in Appendix B of RFC3779.
     */
    @Test
    public void shouldParseRfc3779AppendixBFirstExample() {
        SortedMap<AddressFamily, IpResourceSet> resources = new TreeMap<AddressFamily, IpResourceSet>();
        resources.put(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(1),
                IpResourceSet.parse("10.0.32.0/20, 10.0.64.0/24, 10.1.0.0/16, 10.2.48.0/20, 10.2.64.0/24, 10.3.0.0/16"));
        resources.put(AddressFamily.IPV6, null);
        assertEquals(resources, parser.derToIpAddressBlocks(Asn1Util.decode(RFC3779_APPENDIX_B_EXAMPLE_1)));
    }

    /**
     * The first example in Appendix B of RFC3779. Note that the example lists
     * 172.16/12, which is incorrect (the encoded example is 176.12/12, 0xb0
     * instead of 0xac).
     */
    @Test
    public void shouldParseRfc3779AppendixBSecondExample() {
        SortedMap<AddressFamily, IpResourceSet> resources = new TreeMap<AddressFamily, IpResourceSet>();
        resources.put(AddressFamily.IPV6, IpResourceSet.parse("2001:0:2::/48"));
        resources.put(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(1),
                IpResourceSet.parse("10.0.0.0/8,176.16.0.0/12"));
        resources.put(AddressFamily.IPV4.withSubsequentAddressFamilyIdentifier(2), null);
        assertEquals(resources, parser.derToIpAddressBlocks(Asn1Util.decode(RFC3779_APPENDIX_B_EXAMPLE_2)));
    }

    @Test
    public void shouldParseExtensionWithoutNullSetsToIpResourceSet() {
        IpResourceSet ipv4ResourceSet = IpResourceSet.parse("10.5.4.0-10.5.15.255, 128.5.0.4/32");
        IpResourceSet ipv6ResourceSet = IpResourceSet.parse("2001:0:200::/39");
        SortedMap<AddressFamily, IpResourceSet> parsed = parser.parseIpAddressBlocks(ENCODED_IP_ADDRESS_BLOCKS_EXTENSION);
        assertEquals(ipv4ResourceSet, parsed.get(AddressFamily.IPV4));
        assertEquals(ipv6ResourceSet, parsed.get(AddressFamily.IPV6));
    }

    @Test
    public void shouldSupportIpv4OnlyInheritance() {
        SortedMap<AddressFamily, IpResourceSet> parsed = parser.parseIpAddressBlocks(ENCODED_IPV4_ONLY_INHERITED);

        assertTrue(parsed.containsKey(AddressFamily.IPV4) && parsed.get(AddressFamily.IPV4) == null);
        assertNotNull(parsed.get(AddressFamily.IPV6));
    }

    @Test
    public void shouldSupportIpv4AndIpv6Inheritance() {
        SortedMap<AddressFamily, IpResourceSet> parsed = parser.parseIpAddressBlocks(ENCODED_IPV4_AND_IPV6_INHERITED);

        assertTrue(parsed.containsKey(AddressFamily.IPV4) && parsed.get(AddressFamily.IPV4) == null);
        assertTrue(parsed.containsKey(AddressFamily.IPV6) && parsed.get(AddressFamily.IPV6) == null);
    }

    @Test
    public void shouldSupportAsIdentifierInheritance() {
        assertNull(parser.parseAsIdentifiers(ENCODED_AS_IDENTIFIERS_INHERITED));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailToParseExtensionWithNullSet() {
        parser.parseIpAddressBlocks(RFC3779_APPENDIX_B_EXAMPLE_1);
    }

    @Test
    public void shouldDecodeAsRange() {
        assertEquals(ASN_127.upTo(ASN_128), parser.derToAsRange(Asn1Util.decode(ENCODED_ASN_127_TO_128)));
        assertEquals(ASN_0.upTo(ASN_65535_65535), parser.derToAsRange(Asn1Util.decode(ENCODED_ASN_0_TO_65535_65535)));
    }

    @Test
    public void shouldDecodeAsIdOrRange() {
        assertEquals(ASN_127, parser.derToAsIdOrRange(Asn1Util.decode(ENCODED_ASN_127)));
        assertEquals(ASN_127.upTo(ASN_128), parser.derToAsIdOrRange(Asn1Util.decode(ENCODED_ASN_127_TO_128)));
    }

    @Test
    public void shouldDecodeAsIdsOrRanges() {
        IpResourceSet resources = new IpResourceSet(ASN_412_233, ASN_127.upTo(ASN_128));
        assertEquals(resources, parser.derToAsIdsOrRanges(Asn1Util.decode(ENCODED_AS_IDS_OR_RANGES)));
    }

    @Test
    public void shouldDecodeAsIdentifierChoice() {
        IpResourceSet resources = new IpResourceSet(ASN_412_233, ASN_127.upTo(ASN_128));
        assertNull(parser.derToAsIdentifierChoice(Asn1Util.decode(ENCODED_NULL)));
        assertEquals(resources, parser.derToAsIdentifierChoice(Asn1Util.decode(ENCODED_AS_IDS_OR_RANGES)));
    }

    /**
     * The example in Appendix C of RFC3779.
     *
     * @
     */
    @Test
    public void shouldDecodeRfc3779AppendixCExample() {
        IpResourceSet asnResources = IpResourceSet.parse("AS135, AS3000-AS3999, AS5001");
        IpResourceSet[] result = parser.derToAsIdentifiers(Asn1Util.decode(RFC3779_APPENDIX_C_EXAMPLE));
        assertEquals(asnResources, result[0]);
        assertNull(result[1]);
    }

    @Test
    public void shouldDecodeAsIdentifiers() {
        IpResourceSet resources = new IpResourceSet(ASN_412_233, ASN_127.upTo(ASN_128));
        assertEquals(resources, parser.parseAsIdentifiers(ENCODED_AS_IDENTIFIERS_EXTENSION));
    }

}
