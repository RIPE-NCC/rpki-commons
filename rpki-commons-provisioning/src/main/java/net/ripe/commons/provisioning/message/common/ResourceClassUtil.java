package net.ripe.commons.provisioning.message.common;

import java.net.URI;
import java.util.List;

public final class ResourceClassUtil {

    private ResourceClassUtil() {
    }

    static boolean hasRsyncUri(List<URI> uris) {
        boolean rsyncUriFound = false;

        if (uris == null) {
            return rsyncUriFound;
        }

        for (URI uri : uris) {
            if (uri.toString().startsWith("rsync:")) {
                rsyncUriFound = true;
                break;
            }
        }
        return rsyncUriFound;
    }

    public static boolean validateAsn(String[] asNumbers) {
        boolean isValid = true;

        if (asNumbers != null) {
            for (String asnNumber : asNumbers) {
                isValid &= !asnNumber.startsWith("AS");
            }
        }

        return isValid;
    }
}
