package net.ripe.rpki.commons.validation.roa;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;

/**
 * A route announced on BGP.
 */
@EqualsAndHashCode
@Getter(onMethod_ = {@Override})
public final class AnnouncedRoute implements Serializable, RouteData {
    private static final long serialVersionUID = 1L;
    private final Asn originAsn;
    private final IpRange prefix;

    public AnnouncedRoute(Asn originAsn, IpRange prefix) {
        Validate.notNull(originAsn, "origin is required");
        Validate.isTrue(prefix.isLegalPrefix(), "Prefix must be legal");
        this.originAsn = originAsn;
        this.prefix = prefix;
    }
    @Override
    public String toString() {
        return "AnnouncedRoute [originAsn=" + originAsn + ", prefix=" + prefix + "]";
    }
}