package net.ripe.rpki.commons.crypto.util;

import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceType;
import net.ripe.ipresource.Ipv4Address;
import net.ripe.ipresource.UniqueIpResource;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.junit.jupiter.api.Test;

import static net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoderTest.*;
import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class Asn1UtilTest {

    @Test
    public void shouldFailToParseNonZeroPadBits() {
        byte[] WRONG_ENCODED_IPV4_10_5_0_0_23 = {0x03, 0x04, 0x01, 0x0a, 0x05, 0x01};
        assertThatThrownBy(() -> parseIpAddressAsPrefix(IpResourceType.IPv4, decode(WRONG_ENCODED_IPV4_10_5_0_0_23)))
                .isIn(IllegalArgumentException.class);
    }

    @Test
    public void shouldFailIPv4ParsingWhenNoValidDerBitStringFoundP() {
        // bouncy castle 1.70+ catches this invalid case when decoding
        byte[] WRONG_ENCODED_IPV4_10_5_0_0_23 = {0x05, 0x04, 0x01, 0x0a, 0x05, 0x01};
        assertThatThrownBy(() -> parseIpAddressAsPrefix(IpResourceType.IPv4, decode(WRONG_ENCODED_IPV4_10_5_0_0_23)))
                .isInstanceOf(Asn1UtilException.class);
    }

    @Test
    public void shouldParseIpv4Address() {
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_0_0_0_0_0))).isEqualTo(IpResource.parse("0.0.0.0/0"));
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_5_0_4_32))).isEqualTo(IpResource.parse("10.5.0.4/32"));
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_5_0_0_23))).isEqualTo(IpResource.parse("10.5.0.0/23"));
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_64_0_0_12))).isEqualTo(IpResource.parse("10.64.0.0/12"));
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_10_64_0_0_20))).isEqualTo(IpResource.parse("10.64.0.0/20"));
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv4, decode(ENCODED_IPV4_128_5_0_4_32))).isEqualTo(IpResource.parse("128.5.0.4/32"));
    }

    @Test
    public void shouldFailToParseNonZeroPadBitsIpv4Address() {
        byte[] WRONG_ENCODED_IPV4_10_5_0_0 = {0x03, 0x03, 0x01, 0x0a, 0x05};
        assertThatThrownBy(() -> parseIpAddress(IpResourceType.IPv4, decode(WRONG_ENCODED_IPV4_10_5_0_0), false))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void shouldParseIpv6Addresses() {
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv6, decode(ENCODED_IPV6_2001_0_200_3_0_0_0_1_128)))
                .isEqualTo(IpResource.parse("2001:0:200:3::1/128"));
        assertThat(parseIpAddressAsPrefix(IpResourceType.IPv6, decode(ENCODED_IPV6_2001_0_200_39))).isEqualTo(IpResource.parse("2001:0:200::/39"));
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
        assertThat(parseAsId(decode(ENCODED_ASN_0))).isEqualTo(ASN_0);
        assertThat(parseAsId(decode(ENCODED_ASN_127))).isEqualTo(ASN_127);
        assertThat(parseAsId(decode(ENCODED_ASN_128))).isEqualTo(ASN_128);
        assertThat(parseAsId(decode(ENCODED_ASN_412_233))).isEqualTo(ASN_412_233);
        assertThat(parseAsId(decode(ENCODED_ASN_65535_65535))).isEqualTo(ASN_65535_65535);
    }

    @Test
    public void shouldFailOnOutOfRangeAsn() {
        assertThatThrownBy(() -> parseAsId(new ASN1Integer(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void HandleZeroSlashEight() {
        String expected = "0.12.0.0";
        UniqueIpResource ip = Ipv4Address.parse(expected);
        int bits = 16;
        DERBitString bitString = Asn1Util.resourceToBitString(ip, bits);

        IpRange ipAfter = Asn1Util.parseIpAddressAsPrefix(IpResourceType.IPv4, bitString);
        String actual = ipAfter.toString();

        assertThat(actual).isEqualTo(expected + "/16")
                .withFailMessage("The ip addresses should not have mutated!");
    }

    public static void assertEncoded(byte[] expected, ASN1Encodable encodable) {
        byte[] actual = encode(encodable);
        assertThat(actual).isEqualTo(expected);
    }
}
