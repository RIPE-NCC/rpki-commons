package net.ripe.rpki.commons.validation.properties;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import java.net.URI;

public class URIGen extends Generator<URI> {
    public final int HIER_AUTHORITY_PATH = 0;
    public final int HIER_PATH_ABSOLUTE = 1;
    public final int HIER_PATH_ROOTLESS = 2;
    public final int HIER_PATH_EMPTY = 3;

    public final int HOST_REG_NAME = 0;
    public final int HOST_IPV4 = 1;
    public final int HOST_IPV6 = 2;

    private final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private final String NUMERIC = "0123456789";

    private SourceOfRandomness r;

    public URIGen() {
        super(URI.class);
    }

    @Override
    public URI generate(SourceOfRandomness r, GenerationStatus generationStatus) {
        this.r = r;

        try {
            return buildURI();
        } catch (Exception exception) {
            // bad uri, interesting but ok or invalid options for uri generation
            System.err.println(exception.getMessage());
            exception.printStackTrace();
        }

        return null;
    }

    private URI buildURI() throws Exception {
        String uri = hierPart(scheme()) + query() + fragment();
        return new URI(uri);
    }

    private String hierPart(String scheme) throws Exception {
        switch (r.nextInt(0, 3)) {
            case HIER_AUTHORITY_PATH: return scheme + authority() + path();
            case HIER_PATH_ABSOLUTE: return scheme + path();
            case HIER_PATH_ROOTLESS: return scheme + path("");
            case HIER_PATH_EMPTY: return "";
            default: throw new Exception("Invalid option for hierPart");
        }
    }

    private String scheme() {
        String[] commonScheme = { "http", "https", "ftp", "ftps", "mailto", "file", "data", "irc", "blob", "sftp" };
        int pickScheme = r.nextInt(0, commonScheme.length);

        if (pickScheme == commonScheme.length) {
            String SCHEME = UPPERCASE + LOWERCASE + NUMERIC + "+.-";
            return randomString(1, 1, UPPERCASE + LOWERCASE, false)
                     + randomString(2, 100, SCHEME, false) + ":";
        }

        return commonScheme[pickScheme] + ":";
    }

    private String authority() throws Exception {
        return "//" + userinfo() + host() + port();
    }

    private String userinfo() {
        if (r.nextBoolean()) {
            return "";
        }

        return randomString(1, 100) + ":" + randomString(0, 100) + "@";
    }

    private String host() throws Exception {
        switch (r.nextInt(0,2)) {
            case HOST_REG_NAME: return regName();
            case HOST_IPV4: return ip4();
            case HOST_IPV6: return ipv6();
            default: throw new Exception("Invalid option for host");
        }
    }

    private String regName() {
        String REG = UPPERCASE + LOWERCASE + NUMERIC + ".-";
        return randomString(1, 255, REG);
    }

    private String ip4() {
        return r.nextInt(0,255) + "." + r.nextInt(0,255) + "." + r.nextInt(0,255) + "." + r.nextInt(0,255);
    }

    private String ipv6() {
        return String.format("%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
                r.nextInt(0, 65535), r.nextInt(0, 65535), r.nextInt(0, 65535), r.nextInt(0, 65535),
                r.nextInt(0, 65535), r.nextInt(0, 65535), r.nextInt(0, 65535), r.nextInt(0, 65535));
    }

    private String port() {
        if (r.nextBoolean()) {
            return "";
        }

        return ":" + r.nextInt(0, 65535);
    }

    private String path() {
        return path("/");
    }

    private String path(String append) {
        String PATH = LOWERCASE + UPPERCASE + NUMERIC + ".+;=";
        return append +
                randomString(1, 1, PATH) +
                randomString(1, 255, PATH + "/");
    }

    private String query() {
        if (r.nextBoolean()) {
            return "";
        }

        String QUERY = LOWERCASE + UPPERCASE + NUMERIC + "/?=";
        return "?" + randomString(1, 255, QUERY);
    }

    private String fragment() {
        if (r.nextBoolean()) {
            return "";
        }

        String FRAGMENT = LOWERCASE + UPPERCASE + NUMERIC + "/?=";
        return "#" + randomString(1, 255, FRAGMENT);
    }

    private String randomString(int minLength, int maxLength) {
        return randomString(minLength, maxLength, LOWERCASE + UPPERCASE + NUMERIC);
    }

    private String randomString(int minLength, int maxLength, String possibleCharacters) {
        return randomString(minLength, maxLength, possibleCharacters, true);
    }

    private String randomString(int minLength, int maxLength, String possibleCharacters, boolean genEncodedChars) {
        String HEX_DIGIT = "0123456789ABCDEF";
        StringBuilder sb = new StringBuilder();
        int len = r.nextInt(minLength, maxLength);

        for (int i = 0; i < len; i++) {
            if (genEncodedChars) {
                int charIdx = r.nextInt(0, possibleCharacters.length());
                if (charIdx == possibleCharacters.length()) {
                    sb.append("%").append(randomString(2, 2, HEX_DIGIT, false));
                } else {
                    sb.append(possibleCharacters.charAt(charIdx));
                }
            } else {
                sb.append(possibleCharacters.charAt(r.nextInt(0, possibleCharacters.length() - 1)));
            }
        }

        return sb.toString();
    }
}
