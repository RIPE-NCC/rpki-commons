package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;

import java.util.Comparator;

/**
 * Represents a Validated Roa Prefix
 */
public interface RoaPrefixData extends Comparable<RoaPrefixData> {
    Comparator<RoaPrefixData> ROA_PREFIX_DATA_COMPARATOR = Comparator.comparing(RoaPrefixData::getAsn).thenComparing(RoaPrefixData::getPrefix).thenComparing(RoaPrefixData::getMaximumLength);
    Asn getAsn();

    /**
     * @return The prefix of the entity. <emph>MUST</emph> be a prefix and not a IP range
     */
    IpRange getPrefix();

    /**
     * @return The maximum length of the VRP. The maximum length <emph>MUST</emph> be in the range (inclusive) between
     * the prefix length and the length of addresses for the address family.
     */
    int getMaximumLength();

    @Override
    default int compareTo(RoaPrefixData o) {
        return ROA_PREFIX_DATA_COMPARATOR.compare(this, o);
    }

    default AllowedRoute toAllowedRoute() {
        return new AllowedRoute(getAsn(), getPrefix(), getMaximumLength());
    }
}
