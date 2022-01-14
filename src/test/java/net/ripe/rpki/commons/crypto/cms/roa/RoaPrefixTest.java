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
}
