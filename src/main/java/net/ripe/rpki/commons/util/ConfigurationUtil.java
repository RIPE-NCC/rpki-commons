package net.ripe.rpki.commons.util;

public class ConfigurationUtil {
    private static final String USER_HOME = System.getProperty("user.home");

    public static String interpolate(String value) {
        return value.replaceAll("\\$\\{HOME\\}", USER_HOME);
    }

    public static boolean isTemporary(String dir) {
        return dir.startsWith(USER_HOME);
    }

    public static String getTempDirectory() {
        String tmpdir = System.getProperty("java.io.tmpdir", "/tmp");
        final String prefix = "/tmp/RPKI-";
        if (tmpdir.startsWith(prefix)) {
            // We want to have some stable directory to be
            // able running tests on CI with SELinux set up
            return tmpdir.replaceFirst("\\/tmp\\/", "/tmp/RPKI-RSYNC/");
        }
        return tmpdir;
    }
}
