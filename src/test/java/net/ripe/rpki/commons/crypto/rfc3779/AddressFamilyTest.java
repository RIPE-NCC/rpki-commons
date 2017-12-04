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
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import org.junit.Test;

import static net.ripe.rpki.commons.crypto.rfc3779.AddressFamily.*;
import static org.junit.Assert.*;


// ESCA-JAVA0076:
public class AddressFamilyTest {

    private static final AddressFamily IPV6_5 = IPV6.withSubsequentAddressFamilyIdentifier(5);
    private static final AddressFamily IPV4_2 = IPV4.withSubsequentAddressFamilyIdentifier(2);
    private static final AddressFamily IPV4_1 = IPV4.withSubsequentAddressFamilyIdentifier(1);
    private static final AddressFamily IPV6_2 = IPV6.withSubsequentAddressFamilyIdentifier(2);

    @Test
    public void shouldBeEqualBasedOnAfiAndSafi() {
        assertEquals(IPV4, IPV4);
        assertEquals(0, IPV4.compareTo(IPV4));

        assertEquals(IPV6, IPV6);
        assertEquals(0, IPV6.compareTo(IPV6));

        assertEquals(IPV6_2, IPV6_2);
        assertEquals(0, IPV6_2.compareTo(IPV6_2));

        assertEquals(IPV6, IPV6_2.withoutSubsequentAddressFamilyIdentifier());
    }

    @Test
    public void shouldOrderIpv4BeforeIpv6() {
        assertTrue(IPV4.compareTo(IPV6) < 0);
        assertTrue(IPV6.compareTo(IPV4) > 0);
    }

    @Test
    public void shouldOrderLowerSafiBeforeHigherSafi() {
        assertTrue(IPV4_1.compareTo(IPV4_2) < 0);
        assertTrue(IPV6_5.compareTo(IPV6_2) > 0);
    }

    @Test
    public void shouldOrderAddressFamilyWithoutSafiBeforeAddressFamilyWithSafi() {
        assertTrue(IPV4.compareTo(IPV4_2) < 0);
        assertTrue(IPV4_2.compareTo(IPV4) > 0);
    }

    @Test
    public void shouldConvertToDerOctetString() {
        byte[] encodedIpv4 = {0x00, 0x01};
        assertArrayEquals(encodedIpv4, IPV4.toDer().getOctets());

        byte[] encodedIpv4Multicast = {0x00, 0x01, 0x02};
        assertArrayEquals(encodedIpv4Multicast, IPV4_2.toDer().getOctets());

        byte[] encodedIpv6 = {0x00, 0x02};
        assertArrayEquals(encodedIpv6, IPV6.toDer().getOctets());

        byte[] encoded = {(byte) 0x80, (byte) 0xf0, (byte) 0x88};
        assertArrayEquals(encoded, new AddressFamily(0x80f0, 0x88).toDer().getOctets());
    }

    @Test
    public void shouldConstructFromDer() {
        byte[] encodedIpv4 = {0x04, 0x02, 0x00, 0x01};
        assertEquals(IPV4, fromDer(Asn1Util.decode(encodedIpv4)));

        byte[] encodedIpv4Multicast = {0x04, 0x03, 0x00, 0x01, 0x02};
        assertEquals(IPV4_2, fromDer(Asn1Util.decode(encodedIpv4Multicast)));

        byte[] encodedIpv6 = {0x04, 0x02, 0x00, 0x02};
        assertEquals(IPV6, fromDer(Asn1Util.decode(encodedIpv6)));

        byte[] encoded = {0x04, 0x03, (byte) 0x80, (byte) 0xf0, (byte) 0x88};
        assertEquals(new AddressFamily(0x80f0, 0x88), fromDer(Asn1Util.decode(encoded)));

    }

    @Test
    public void shouldConvertToIpResourceType() {
        assertEquals(IpResourceType.IPv4, IPV4.toIpResourceType());
        assertEquals(IpResourceType.IPv6, IPV6.toIpResourceType());
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailToConvertToIpResourceTypeForUnknownAfi() {
        new AddressFamily(25).toIpResourceType();
    }
}
