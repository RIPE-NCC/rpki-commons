package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;
import java.util.Comparator;

/**
 * A route announced on BGP.
 */
public final class AnnouncedRoute implements Serializable {
    private static final long serialVersionUID = 1L;

    public static final Comparator<AnnouncedRoute> ASN_PREFIX_COMPARATOR = new Comparator<AnnouncedRoute>() {
        @Override
        public int compare(AnnouncedRoute o1, AnnouncedRoute o2) {
            int rc = o1.getOriginAsn().compareTo(o2.getOriginAsn());
            if (rc != 0) {
                return rc;
            }
            return o1.getPrefix().compareTo(o2.getPrefix());
        }
    };

    private final Asn originAsn;
    private final IpRange prefix;

    public AnnouncedRoute(Asn originAsn, IpRange prefix) {
        Validate.notNull(originAsn, "origin is required");
        Validate.isTrue(prefix.isLegalPrefix(), "Prefix must be legal");
        this.originAsn = originAsn;
        this.prefix = prefix;
    }

    public Asn getOriginAsn() {
        return originAsn;
    }

    public IpRange getPrefix() {
        return prefix;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + originAsn.hashCode();
        result = prime * result + prefix.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        AnnouncedRoute that = (AnnouncedRoute) obj;
        return this.originAsn.equals(that.originAsn) && this.prefix.equals(that.prefix);
    }

    @Override
    public String toString() {
        return "AnnouncedRoute [originAsn=" + originAsn + ", prefix=" + prefix + "]";
    }
}
