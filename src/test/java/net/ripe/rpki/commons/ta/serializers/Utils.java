package net.ripe.rpki.commons.ta.serializers;

public class Utils {
    public static String cleanupBase64(String s) {
        return s.replaceAll("\\s*", "");
    }
}
