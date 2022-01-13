/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.IpRange;
import org.junit.Test;

import static org.junit.Assert.*;


public class RoaPrefixTest {

    @Test
    public void shouldEnsureIpAddressIsValidPrefix() {
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), null);
        try {
            new RoaPrefix(IpRange.parse("10.0.0.0-10.0.2.1"), null);
            fail("ROA prefix requires legal prefix");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void shouldEnsureMaximumLengthValidity() {
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), null);
        try {
            new RoaPrefix(IpRange.parse("10.0.0.0/8"), -1);
            fail("maximum length invalid");
        } catch (IllegalArgumentException expected) {
        }

        new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8);
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), 17);
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), 32);
        new RoaPrefix(IpRange.parse("ffe0::/16"), 128);

        try {
            new RoaPrefix(IpRange.parse("10.0.0.0/8"), 0);
            fail("maximum length invalid");
        } catch (IllegalArgumentException expected) {
        }
        try {
            new RoaPrefix(IpRange.parse("10.0.0.0/8"), 7);
            fail("maximum length invalid");
        } catch (IllegalArgumentException expected) {
        }
        try {
            new RoaPrefix(IpRange.parse("10.0.0.0/8"), 33);
            fail("maximum length invalid");
        } catch (IllegalArgumentException expected) {
        }
        try {
            new RoaPrefix(IpRange.parse("ffe0::/16"), 129);
            fail("maximum length invalid");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testEqualsHashCode() {
        RoaPrefix a = new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8);
        RoaPrefix b = new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8);
        RoaPrefix c = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8);
        assertEquals(a, b);
        assertNotEquals(a, c);
    }

    @Test
    public void testToString() {
        assertEquals("RoaPrefix(prefix=10.0.0.0/8, maximumLength=8)", new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8).toString());
    }
}
