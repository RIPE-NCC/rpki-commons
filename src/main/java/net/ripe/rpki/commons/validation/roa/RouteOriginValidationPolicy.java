package net.ripe.rpki.commons.validation.roa;

import lombok.experimental.UtilityClass;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.etree.IpResourceIntervalStrategy;
import net.ripe.ipresource.etree.NestedIntervalMap;

import java.util.LinkedList;
import java.util.List;


/**
 * See http://tools.ietf.org/html/draft-ietf-sidr-roa-validation-10
 */
@UtilityClass
public class RouteOriginValidationPolicy {

    public static <T extends RoaPrefixData> NestedIntervalMap<IpResource, List<T>> allowedRoutesToNestedIntervalMap(Iterable<T> allowedRoutes) {
        NestedIntervalMap<IpResource, List<T>> result = new NestedIntervalMap<>(IpResourceIntervalStrategy.getInstance());
        for (T allowedRoute : allowedRoutes) {
            List<T> allowed = result.findExact(allowedRoute.getPrefix());
            if (allowed == null) {
                allowed = new LinkedList<>();
                result.put(allowedRoute.getPrefix(), allowed);
            }
            allowed.add(allowedRoute);
        }
        return result;
    }

    public static <T extends RoaPrefixData, U extends RouteData> RouteValidityState validateAnnouncedRoute(NestedIntervalMap<IpResource, ? extends Iterable<T>> allowedRoutes, U announcedRoute) {
        RouteValidityState result = RouteValidityState.UNKNOWN;
        for (var routes : allowedRoutes.findExactAndAllLessSpecific(announcedRoute.getPrefix())) {
            for (T allowedRoute : routes) {
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

    private static <T extends RoaPrefixData, U extends RouteData> RouteValidityState validate(T allowedRoute, U announcedRoute) {
        IpRange announcedPrefix = announcedRoute.getPrefix();

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

    private static <T extends RoaPrefixData> boolean isUnknown(T allowedRoute, IpRange announcedPrefix) {
        // non-intersecting or covering-aggregate
        return !allowedRoute.getPrefix().contains(announcedPrefix);
    }

    private static <T extends RoaPrefixData> boolean isLengthInvalid(T allowedRoute, IpRange announcedPrefix) {
        return announcedPrefix.getPrefixLength() > allowedRoute.getMaximumLength();
    }

    private static <T extends RoaPrefixData, U extends RouteData> boolean isAsnInvalid(T allowedRoute, U announcedRoute) {
        return !allowedRoute.getAsn().equals(announcedRoute.getOriginAsn());
    }

}
