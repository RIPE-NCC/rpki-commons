package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;

import java.util.Comparator;

public interface RouteData extends Comparable<RouteData> {
    Comparator<RouteData> ROUTE_DATA_COMPARATOR = Comparator.comparing(RouteData::getOriginAsn).thenComparing(RouteData::getPrefix);

    Asn getOriginAsn();

    /**
     * @return The prefix of the entity. <b>MUST</b> be a prefix and not a IP range
     */
    IpRange getPrefix();

    @Override
    default int compareTo(RouteData o) {
        return ROUTE_DATA_COMPARATOR.compare(this, o);
    }
}
