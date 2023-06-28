package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.IpRange;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;


public class RoaPrefixTest {
    @Test
    public void shouldSortRoaPrefixByPrefixThenMaximumLength() {
        var p1 = new RoaPrefix(IpRange.parse("10.0.0.0/8"));
        var p2 = new RoaPrefix(IpRange.parse("11.0.0.0/8"));
        var p2_8 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8);
        var p2_24 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 24);

        var prefixList = new ArrayList(List.of(p2_24, p1, p2_8, p2));

        // Static case of re-sorting a list in wrong order
        assertThat(new TreeSet(List.of(p2_24, p1, p2_8, p2)))
                .containsExactly(p1, p2, p2_8, p2_24);

        // But test a number of random shuffles as well
        for (int i=0; i < 16; i++) {
            Collections.shuffle(prefixList);
            assertThat(new TreeSet(prefixList))
                    .containsExactly(p1, p2, p2_8, p2_24);
        }
    }


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
