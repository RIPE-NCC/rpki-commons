package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.crypto.cms.roa.Roa;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


/**
 * A route allowed by a ROA configuration.
 */
public class AllowedRoute extends EqualsSupport implements Serializable {
    private static final long serialVersionUID = 1L;

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
        List<AllowedRoute> result = new ArrayList<AllowedRoute>();
        for (Roa roa : roas) {
            for (RoaPrefix roaPrefix : roa.getPrefixes()) {
                result.add(new AllowedRoute(roa.getAsn(), roaPrefix.getPrefix(), roaPrefix.getEffectiveMaximumLength()));
            }
        }
        return result;
    }

    public Asn getAsn() {
        return asn;
    }

    public IpRange getPrefix() {
        return prefix;
    }

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
