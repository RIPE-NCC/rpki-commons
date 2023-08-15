package net.ripe.rpki.commons.validation.properties;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.generator.GeneratorConfiguration;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

import java.lang.annotation.*;
import java.net.URI;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

public class URIGen extends Generator<URI> {
    public static final int HOST_REG_NAME = 0;
    public static final int HOST_IPV4 = 1;
    public static final int HOST_IPV6 = 2;

    private final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private final String NUMERIC = "0123456789";

    private String[] schemes;

    private SourceOfRandomness r;

    @Target({PARAMETER, FIELD, ANNOTATION_TYPE, TYPE_USE})
    @Retention(RUNTIME)
    @GeneratorConfiguration
    public @interface URIControls {
        String[] schemas();
    }

    public URIGen() {
        super(URI.class);
    }

    public URIGen(String[] schemas) {
        super(URI.class);

        this.schemes = schemas;
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

    public void configure(URIControls uriControls) {
        schemes = uriControls.schemas();
    }

    private URI buildURI() throws Exception {
        String uri = scheme() + authority() + path() + query() + fragment();
        return new URI(uri);
    }

    private String scheme() {
        int pickScheme = r.nextInt(0, schemes.length - 1);
        return schemes[pickScheme] + ":";
    }

    private String authority() throws Exception {
        return "//" + userinfo() + host() + port();
    }

    private String userinfo() {
        if (r.nextBoolean()) {
            return "";
        }

        String REG = LOWERCASE + UPPERCASE + NUMERIC;

        return randomString(1, 100, REG, false) + ":" + randomString(0, 100, REG, false) + "@";
    }

    private String host() throws Exception {
        return switch (r.nextInt(0, 2)) {
            case HOST_REG_NAME -> regName();
            case HOST_IPV4 -> ipv4();
            case HOST_IPV6 -> ipv6();
            default -> throw new Exception("Invalid option for host");
        };
    }

    private String regName() {
        int maxLength = 254;
        int sectionMaxLength;
        String REG = UPPERCASE + LOWERCASE + NUMERIC;
        String REG_START = UPPERCASE + LOWERCASE;
        boolean noDash = true;

        int numSections = r.nextInt(1, 3);
        String[] sections = new String[numSections];

        for (int i = 0; i < numSections && maxLength > 0; i++) {
            sectionMaxLength = Integer.min(20, maxLength - 3);

            sections[i] = randomString(1, 1, REG_START, false)
                    + randomString(1, sectionMaxLength - 1, REG, false);

            maxLength = maxLength - sections[i].length();

            if (noDash && r.nextBoolean() && maxLength > 0 && sections[i].length() > 3) {
                int placeDash = r.nextInt(1, sections[i].length() - 2);
                sections[i] = sections[i].substring(0, placeDash) + "-" + sections[i].substring(placeDash);

                noDash = false;
                maxLength--;
            }
        }

        return String.join(".", sections);
    }

    private String ipv4() {
        return r.nextInt(0,255) + "." + r.nextInt(0,255) + "." + r.nextInt(0,255) + "." + r.nextInt(0,255);
    }

    private String ipv6() {
        return String.format("[%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X]",
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
        String PATH = LOWERCASE + UPPERCASE + NUMERIC + ".+;=";
        return "/" +
                randomString(1, 1, PATH, true) +
                randomString(1, 255, PATH + "/", true);
    }

    private String query() {
        if (r.nextBoolean()) {
            return "";
        }

        String QUERY = LOWERCASE + UPPERCASE + NUMERIC + "/?=";
        return "?" + randomString(1, 255, QUERY, true);
    }

    private String fragment() {
        if (r.nextBoolean()) {
            return "";
        }

        String FRAGMENT = LOWERCASE + UPPERCASE + NUMERIC + "/?=";
        return "#" + randomString(1, 255, FRAGMENT, true);
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
