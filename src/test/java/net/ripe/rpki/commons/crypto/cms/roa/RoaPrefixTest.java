package net.ripe.rpki.commons.crypto.cms.roa;

import com.google.common.collect.Sets;
import net.ripe.ipresource.IpRange;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.fail;


public class RoaPrefixTest {
    @Test
    public void shouldEqualWhenSemanticallyEqual() {
        var s1 = new RoaPrefix(IpRange.parse("10.0.0.0/8"));
        var s1_null = new RoaPrefix(IpRange.parse("10.0.0.0/8"), null);
        var s1_8 = new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8);

        var s1_32 = new RoaPrefix(IpRange.parse("10.0.0.0/8"), 32);

        var s2 = new RoaPrefix(IpRange.parse("11.0.0.0/8"));
        var s2_8 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8);

        // hashcode contract
        assertThat(s1.hashCode()).isEqualTo(s1_null.hashCode());
        assertThat(s1.hashCode()).isEqualTo(s1_8.hashCode());

        // not equal when differing prefix or differing maxlength
        assertThat(s1).isNotEqualTo(s1_32);
        assertThat(s1).isNotEqualTo(s2);
        assertThat(s1).isNotEqualTo(s2_8);
        // or whatever
        assertThat(s1).isNotEqualTo("🤷‍♂️");

        // reflexive
        assertThat(s1).isEqualTo(s1);
        assertThat(s1).isEqualTo(s1_null);
        assertThat(s1).isEqualTo(s1_8);

        // symmetric
        assertThat(s1_8).isEqualTo(s1);
        assertThat(s1_null).isEqualTo(s1);

        // transitive
        assertThat(s1).isEqualTo(s1_null);
        assertThat(s1_null).isEqualTo(s1_8);
        // =>
        assertThat(s1).isEqualTo(s1_8);
    }

    @Test
    public void shouldSortRoaPrefixByPrefixThenMaximumLength() {
        var p1 = new RoaPrefix(IpRange.parse("10.0.0.0/8"));
        var p2 = new RoaPrefix(IpRange.parse("11.0.0.0/8"));
        // An equal copy of p2
        var p2_8 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 8);
        var p2_24 = new RoaPrefix(IpRange.parse("11.0.0.0/8"), 24);

        var prefixList = new ArrayList(List.of(p2_24, p1, p2_8, p2));

        // Static case of re-sorting a list in wrong order
        var toSort = new ArrayList(List.of(p2_24, p1, p2_8, p2));
        Collections.sort(toSort);
        assertThat(toSort).containsExactly(p1, p2, p2_8, p2_24);

        // **We can not use sets here, because that would deduplicate, i.e p2_8 is gone:
        assertThat(new TreeSet<>(prefixList)).hasSize(prefixList.size()-1);

        // But test a number of random shuffles as well
        for (int i=0; i < 16; i++) {
            Collections.shuffle(prefixList);
            toSort = new ArrayList(prefixList);
            Collections.sort(toSort);
            assertThat(toSort).containsExactly(p1, p2, p2_8, p2_24);
        }
    }


    @Test
    public void shouldEnsureIpAddressIsValidPrefix() {
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), null);

        assertThatThrownBy(() -> new RoaPrefix(IpRange.parse("10.0.0.0-10.0.2.1"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .withFailMessage("ROA prefix requires legal prefix");
    }

    @Test
    public void shouldEnsureMaximumLengthValidity() {
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), null);

        assertThatThrownBy(() -> new RoaPrefix(IpRange.parse("10.0.0.0/8"), -1))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");

        new RoaPrefix(IpRange.parse("10.0.0.0/8"), 8);
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), 17);
        new RoaPrefix(IpRange.parse("10.0.0.0/8"), 32);
        new RoaPrefix(IpRange.parse("ffe0::/16"), 128);

        assertThatThrownBy(() -> new RoaPrefix(IpRange.parse("10.0.0.0/8"), 0))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
        assertThatThrownBy(() -> new RoaPrefix(IpRange.parse("10.0.0.0/8"), 7))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
        assertThatThrownBy(() -> new RoaPrefix(IpRange.parse("10.0.0.0/8"), 33))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
        assertThatThrownBy(() -> new RoaPrefix(IpRange.parse("ffe0::/16"), 129))
            .isInstanceOf(IllegalArgumentException.class)
            .withFailMessage("maximum length invalid");
    }
}
