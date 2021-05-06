/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
        long end   = base | ~mask;

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
