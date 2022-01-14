package net.ripe.rpki.commons.validation.properties;

import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.Ipv4Address;
import net.ripe.ipresource.Ipv6Address;

import java.math.BigInteger;

public class ResourceGenerator {

    static IpResource generateIpResource(SourceOfRandomness sourceOfRandomness) {
        final int what = sourceOfRandomness.nextInt(20);
        if (what < 3)
            // sometimes generate ASNs
            return generateAsn(sourceOfRandomness);
        else if (what < 15)
            // much more often generate IPv4
            return generateV4Prefix(sourceOfRandomness);
        else
            // less often generate IPv6
            return generateV6Prefix(sourceOfRandomness);
    }

    static IpResource generateAsn(SourceOfRandomness sourceOfRandomness) {
        return new Asn(sourceOfRandomness.nextLong(Asn.ASN_MIN_VALUE, Asn.ASN32_MAX_VALUE));
    }

    /**
     * Prefix (int this case /16) is a range between
     * xxx.xxx.0.0 and xxx.xxx.255.255
     * so generate a random number (base), random mask
     * and the prefix will be between
     *  - base with the mask on top (i.e. after-mask bits set to 0)
     *  - and base with the after-mask bits set to 1
     */
    static IpResource generateV4Prefix(SourceOfRandomness sourceOfRandomness) {
        final long maxV4Ip = 0xFFFFFFFFL;
        final long base = sourceOfRandomness.nextLong(1, maxV4Ip);
        final int prefixLength = sourceOfRandomness.nextInt(8, 32);

        final long mask = maxV4Ip << (32 - prefixLength);
        long begin = base & mask;
        long end   = base | ~mask & maxV4Ip;

        return IpRange.range(new Ipv4Address(begin), new Ipv4Address(end));
    }

    private static final BigInteger MAX_IPV6 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    /**
     * The same as for Ipv4 but the numbers are bigger.
     */
    static IpResource generateV6Prefix(SourceOfRandomness sourceOfRandomness) {
        final BigInteger base = sourceOfRandomness.nextBigInteger(128);
        final int prefixLength = sourceOfRandomness.nextInt(46, 128);

        final BigInteger mask = MAX_IPV6.shiftLeft(128 - prefixLength);
        final BigInteger begin = base.and(mask);
        final BigInteger end   = base.or(mask.not()).and(MAX_IPV6);

        return IpRange.range(new Ipv6Address(begin), new Ipv6Address(end));
    }
}
