package net.ripe.commons.certification.cms.roa;

import static junit.framework.Assert.*;
import net.ripe.ipresource.IpRange;

import org.junit.Test;


public class RoaPrefixTest {

    @Test
    public void shouldEnsureIpAddressIsValidPrefix() {
        assertTrue(new RoaPrefix(IpRange.parse("10.0.0.0/8"), null).isValidPrefix());
        assertFalse(new RoaPrefix(IpRange.parse("10.0.0.0-10.0.2.1"), null).isValidPrefix());
    }

    @Test
    public void shouldEnsureMaximumLengthValidity() {
        assertTrue(new RoaPrefix(IpRange.parse("10.0.0.0/8"), null).isMaximumLengthValid());
        assertFalse(new RoaPrefix(IpRange.parse("10.0.0.0/8"), -1).isMaximumLengthValid());
        assertTrue(new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8).isMaximumLengthValid());
        assertTrue(new RoaPrefix(IpRange.parse("10.0.0.0/8"), 17).isMaximumLengthValid());
        assertTrue(new RoaPrefix(IpRange.parse("10.0.0.0/8"), 32).isMaximumLengthValid());
        assertTrue(new RoaPrefix(IpRange.parse("ffe0::/16"), 128).isMaximumLengthValid());
        assertFalse(new RoaPrefix(IpRange.parse("10.0.0.0/8"), 0).isMaximumLengthValid());
        assertFalse(new RoaPrefix(IpRange.parse("10.0.0.0/8"), 7).isMaximumLengthValid());
        assertFalse(new RoaPrefix(IpRange.parse("10.0.0.0/8"), 33).isMaximumLengthValid());
        assertFalse(new RoaPrefix(IpRange.parse("ffe0::/16"), 129).isMaximumLengthValid());
    }
}
