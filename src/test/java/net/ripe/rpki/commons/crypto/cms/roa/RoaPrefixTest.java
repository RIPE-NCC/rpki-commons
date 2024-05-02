package net.ripe.rpki.commons.crypto.cms.roa;

import com.google.common.collect.Lists;
import com.google.common.testing.EqualsTester;
import net.ripe.ipresource.IpRange;
import org.junit.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.*;


public class RoaPrefixTest {

    public static final IpRange IP_RANGE_10_0_0_0_8 = IpRange.parse("10.0.0.0/8");
    public static final IpRange IP_RANGE_FFE0_16 = IpRange.parse("ffe0::/16");

    @Test
    public void shouldEqualWhenSemanticallyEqual() {
        // recall: EqualsTester includes a test against an artibtrary object of another class
        new EqualsTester()
                .addEqualityGroup(
                        new RoaPrefix(IP_RANGE_10_0_0_0_8),
                          new RoaPrefix(IP_RANGE_10_0_0_0_8, null),
                          new RoaPrefix(IP_RANGE_10_0_0_0_8, 8)
                ).addEqualityGroup(
                        new RoaPrefix(IP_RANGE_10_0_0_0_8, 32)
                ).addEqualityGroup(
                        new RoaPrefix(IpRange.parse("11.0.0.0/8")),
                        new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8)
                ).testEquals();
    }

    @Test
    public void testCalculateEffectiveLength() {
        var p2 = new RoaPrefix(IpRange.parse("11.0.0.0/8"));
        // An equal copy of p2
        var p2_8 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8);
        var p2_32 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 32);

        // implict maximum length is the prefix length
        assertThat(p2.getEffectiveMaximumLength()).isEqualTo(8);
        assertThat(p2_8.getEffectiveMaximumLength()).isEqualTo(8);
        // and effective maximum length reflects the actual maximum length
        assertThat(p2_32.getEffectiveMaximumLength()).isEqualTo(32);
    }

    @Test
    public void shouldSortRoaPrefixByPrefixThenMaximumLength() {
        var p1 = new RoaPrefix(IP_RANGE_10_0_0_0_8);
        var p2 = new RoaPrefix(IpRange.parse("11.0.0.0/8"));
        // An equal copy of p2
        var p2_8 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8);
        var p2_24 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 24);

        var prefixList = List.of(p2_24, p1, p2_8, p2);

        // Static case of re-sorting a list in wrong order
        var toSortStatic = new ArrayList<>(prefixList);
        Collections.sort(toSortStatic);
        assertThat(toSortStatic).containsExactly(p1, p2, p2_8, p2_24);

        // **We can not use sets here, because that would deduplicate, i.e p2_8 is gone:
        assertThat(new TreeSet<>(prefixList)).hasSize(prefixList.size()-1);

        // But test a number of random shuffles as well
        for (int i=0; i < 16; i++) {
            var toSort = new ArrayList<>(prefixList);
            Collections.shuffle(toSort);
            Collections.sort(toSort);
            assertThat(toSort).containsExactly(p1, p2, p2_8, p2_24);
        }
    }


    @Test
    public void shouldEnsureIpAddressIsValidPrefix() {
        new RoaPrefix(IP_RANGE_10_0_0_0_8, null);
        final var ipRange = IpRange.parse("10.0.0.0-10.0.2.1");

        assertThatThrownBy(() -> new RoaPrefix(ipRange, null))
                .isInstanceOf(IllegalArgumentException.class)
                .withFailMessage("ROA prefix requires legal prefix");
    }

    @Test
    public void shouldEnsureMaximumLengthValidity() {
        new RoaPrefix(IP_RANGE_10_0_0_0_8, null);

        assertThatThrownBy(() -> new RoaPrefix(IP_RANGE_10_0_0_0_8, -1))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");

        new RoaPrefix(IP_RANGE_10_0_0_0_8, 8);
        new RoaPrefix(IP_RANGE_10_0_0_0_8, 17);
        new RoaPrefix(IP_RANGE_10_0_0_0_8, 32);
        new RoaPrefix(IP_RANGE_FFE0_16, 128);

        assertThatThrownBy(() -> new RoaPrefix(IP_RANGE_10_0_0_0_8, 0))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
        assertThatThrownBy(() -> new RoaPrefix(IP_RANGE_10_0_0_0_8, 7))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
        assertThatThrownBy(() -> new RoaPrefix(IP_RANGE_10_0_0_0_8, 33))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
        assertThatThrownBy(() -> new RoaPrefix(IP_RANGE_FFE0_16, 129))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
    }
}
