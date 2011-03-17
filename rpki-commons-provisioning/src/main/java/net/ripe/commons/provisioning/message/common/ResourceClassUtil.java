package net.ripe.commons.provisioning.message.common;

public class ResourceClassUtil {

    static boolean hasRsyncUri(String[] uris) {
        boolean rsyncUriFound = false;

        if (uris == null) {
            return rsyncUriFound;
        }

        for (String uri : uris) {
            if (uri.startsWith("rsync:")) {
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
