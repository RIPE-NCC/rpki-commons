package net.ripe.rpki.commons.validation;

import lombok.Getter;
import lombok.Value;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.roa.Roa;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.validation.roa.AllowedRoute;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AllowedRouteTest {
    @Test
    void testToAllowedRoute_empty() {
        var subject = new RoaDoa(Asn.parse("AS0"), List.of());
        assertThat(AllowedRoute.fromRoas(List.of(subject))).isEmpty();
    }

    @Test
    void testToAllowedRoute_transforms() {
        var testNet1 = IpRange.parse("192.0.2.0/24");
        var testNet2 = IpRange.parse("198.51.100.0/24");

        var docAs1 = Asn.parse("AS65536");
        var docAs2 = Asn.parse("AS65537");

        var subject = new RoaDoa(docAs1, List.of(new RoaPrefix(testNet1, 32)));
        // These roa-prefixes overlap, making the first redundant, but these checks are not applied in this method.
        var subject2 = new RoaDoa(docAs2, List.of(new RoaPrefix(testNet2, 24), new RoaPrefix(testNet2, 32)));

        // A single roa-prefix gets transformed from a single object
        assertThat(AllowedRoute.fromRoas(List.of(subject))).contains(new AllowedRoute(docAs1, testNet1, 32));
        // as well as multiple from multiple
        assertThat(AllowedRoute.fromRoas(List.of(subject, subject2))).contains(
                new AllowedRoute(docAs1, testNet1, 32),
                new AllowedRoute(docAs2, testNet2, 24),
                new AllowedRoute(docAs2, testNet2, 32)
        );
    }

    @Value
    @Getter
    static class RoaDoa implements Roa {
        Asn asn;
        List<RoaPrefix> prefixes;
        ValidityPeriod validityPeriod = new ValidityPeriod(Instant.now(), Instant.now().plus(Duration.standardDays(365)));
    }

}
