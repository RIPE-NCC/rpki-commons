package net.ripe.commons.certification.rfc3779;

import static net.ripe.commons.certification.rfc3779.AddressFamily.*;
import static org.junit.Assert.*;
import net.ripe.commons.certification.Asn1Util;
import net.ripe.ipresource.IpResourceType;

import org.junit.Test;


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
        byte[] encodedIpv4 = { 0x00, 0x01 };
        assertArrayEquals(encodedIpv4, IPV4.toDer().getOctets());

        byte[] encodedIpv4Multicast = { 0x00, 0x01, 0x02 };
        assertArrayEquals(encodedIpv4Multicast, IPV4_2.toDer().getOctets());

        byte[] encodedIpv6 = { 0x00, 0x02 };
        assertArrayEquals(encodedIpv6, IPV6.toDer().getOctets());

        byte[] encoded = { (byte) 0x80, (byte) 0xf0, (byte) 0x88 };
        assertArrayEquals(encoded, new AddressFamily(0x80f0, 0x88).toDer().getOctets());
    }

    @Test
    public void shouldConstructFromDer() {
        byte[] encodedIpv4 = { 0x04, 0x02, 0x00, 0x01 };
        assertEquals(IPV4, fromDer(Asn1Util.decode(encodedIpv4)));

        byte[] encodedIpv4Multicast = { 0x04, 0x03, 0x00, 0x01, 0x02 };
        assertEquals(IPV4_2, fromDer(Asn1Util.decode(encodedIpv4Multicast)));

        byte[] encodedIpv6 = { 0x04, 0x02, 0x00, 0x02 };
        assertEquals(IPV6, fromDer(Asn1Util.decode(encodedIpv6)));

        byte[] encoded = { 0x04, 0x03, (byte) 0x80, (byte) 0xf0, (byte) 0x88 };
        assertEquals(new AddressFamily(0x80f0, 0x88), fromDer(Asn1Util.decode(encoded)));

    }

    @Test
    public void shouldConvertToIpResourceType() {
        assertEquals(IpResourceType.IPv4, IPV4.toIpResourceType());
        assertEquals(IpResourceType.IPv6, IPV6.toIpResourceType());
    }

    @Test(expected=IllegalStateException.class)
    public void shouldFailToConvertToIpResourceTypeForUnknownAfi() {
        new AddressFamily(25).toIpResourceType();
    }
}
