package net.ripe.rpki.commons.provisioning.payload.common;

import java.net.URI;
import java.util.List;

public final class ResourceClassUtil {

    private ResourceClassUtil() {
    }

    static boolean hasRsyncUri(List<URI> uris) {
        if (uris != null) {
            for (URI uri : uris) {
                if (uri.toString().startsWith("rsync:")) {
                    return true;
                }
            }
        }
        return false;
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
