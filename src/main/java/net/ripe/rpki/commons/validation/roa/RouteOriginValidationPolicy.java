package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.etree.IpResourceIntervalStrategy;
import net.ripe.ipresource.etree.NestedIntervalMap;

import java.util.LinkedList;
import java.util.List;


/**
 * See http://tools.ietf.org/html/draft-ietf-sidr-roa-validation-10
 */
public class RouteOriginValidationPolicy {

    public static NestedIntervalMap<IpResource, List<AllowedRoute>> allowedRoutesToNestedIntervalMap(Iterable<? extends AllowedRoute> allowedRoutes) {
        NestedIntervalMap<IpResource, List<AllowedRoute>> result = new NestedIntervalMap<>(IpResourceIntervalStrategy.getInstance());
        for (AllowedRoute allowedRoute : allowedRoutes) {
            List<AllowedRoute> allowed = result.findExact(allowedRoute.getPrefix());
            if (allowed == null) {
                List<AllowedRoute> list = new LinkedList<>();
                list.add(allowedRoute);
                result.put(allowedRoute.getPrefix(), list);
            } else {
                allowed.add(allowedRoute);
            }
        }
        return result;
    }

    public RouteValidityState validateAnnouncedRoute(NestedIntervalMap<IpResource, ? extends Iterable<? extends AllowedRoute>> allowedRoutes, AnnouncedRoute announcedRoute) {
        RouteValidityState result = RouteValidityState.UNKNOWN;
        for (Iterable<? extends AllowedRoute> routes : allowedRoutes.findExactAndAllLessSpecific(announcedRoute.prefix())) {
            for (AllowedRoute allowedRoute : routes) {
                switch (validate(allowedRoute, announcedRoute)) {
                    case VALID:
                        return RouteValidityState.VALID;
                    case INVALID_ASN:
                        result = RouteValidityState.INVALID_ASN;
                        break;
                    case INVALID_LENGTH:
                        result = RouteValidityState.INVALID_LENGTH;
                        break;
                    case UNKNOWN:
                        break;
                }
            }
        }
        return result;
    }

    private RouteValidityState validate(AllowedRoute allowedRoute, AnnouncedRoute announcedRoute) {
        IpRange announcedPrefix = announcedRoute.prefix();

        if (isUnknown(allowedRoute, announcedPrefix)) {
            return RouteValidityState.UNKNOWN;
        }

        if (isAsnInvalid(allowedRoute, announcedRoute)) {
            return RouteValidityState.INVALID_ASN;
        }

        if (isLengthInvalid(allowedRoute, announcedPrefix)) {
            return RouteValidityState.INVALID_LENGTH;
        }

        return RouteValidityState.VALID;
    }

    private boolean isUnknown(AllowedRoute allowedRoute, IpRange announcedPrefix) {
        // non-intersecting or covering-aggregate
        return !allowedRoute.getPrefix().contains(announcedPrefix);
    }

    private boolean isLengthInvalid(AllowedRoute allowedRoute, IpRange announcedPrefix) {
        return !(announcedPrefix.getPrefixLength() <= allowedRoute.getMaximumLength());
    }

    private boolean isAsnInvalid(AllowedRoute allowedRoute, AnnouncedRoute announcedRoute) {
        return !allowedRoute.getAsn().equals(announcedRoute.originAsn());
    }

}
