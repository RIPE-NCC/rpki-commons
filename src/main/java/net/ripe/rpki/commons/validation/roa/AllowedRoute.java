package net.ripe.rpki.commons.validation.roa;

import lombok.EqualsAndHashCode;
import lombok.ToString;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.crypto.cms.roa.Roa;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;


/**
 * A route allowed by a ROA configuration.
 */
@ToString
@EqualsAndHashCode
public class AllowedRoute implements RoaPrefixData, Serializable {
    private static final long serialVersionUID = 2L;

    private final Asn asn;
    private final IpRange prefix;
    private final int maximumLength;

    public AllowedRoute(Asn asn, IpRange prefix, int maximumLength) {
        Validate.notNull(asn, "asn is required");
        Validate.notNull(prefix, "prefix is required");
        Validate.isTrue(maximumLength >= 0 && maximumLength <= prefix.getType().getBitSize(), "maximumLength out of bounds");
        this.asn = asn;
        this.prefix = prefix;
        this.maximumLength = maximumLength;
    }

    public static List<AllowedRoute> fromRoas(List<? extends Roa> roas) {
        return roas.stream()
                .flatMap(roa ->
                        roa.getPrefixes().stream().map(roaPrefix -> new AllowedRoute(roa.getAsn(), roaPrefix.getPrefix(), roaPrefix.getEffectiveMaximumLength()))
                )
                .collect(Collectors.toList());
    }

    @Override
    public Asn getAsn() {
        return asn;
    }

    @Override
    public IpRange getPrefix() {
        return prefix;
    }

    @Override
    public int getMaximumLength() {
        return maximumLength;
    }

    public AnnouncedRoute getAnnouncedRoute() {
        return new AnnouncedRoute(asn, prefix);
    }

    public RoaPrefix getRoaPrefix() {
        Integer maxLen = prefix.getPrefixLength() == maximumLength ? null : maximumLength;
        return new RoaPrefix(prefix, maxLen);
    }
}
