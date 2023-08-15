package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang3.Validate;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.util.Comparator;

/**
 * A route announced on BGP.
 */
public record AnnouncedRoute(@NotNull Asn originAsn, @NotNull IpRange prefix) implements Serializable {
    private static final long serialVersionUID = 1L;

    public static final Comparator<AnnouncedRoute> ASN_PREFIX_COMPARATOR = (o1, o2) -> {
        int rc = o1.originAsn().compareTo(o2.originAsn());
        if (rc != 0) {
            return rc;
        }
        return o1.prefix().compareTo(o2.prefix());
    };

    public AnnouncedRoute {
        Validate.isTrue(prefix.isLegalPrefix(), "Prefix must be legal");
    }

    @Override
    public String toString() {
        return "AnnouncedRoute [originAsn=" + originAsn + ", prefix=" + prefix + "]";
    }
}
