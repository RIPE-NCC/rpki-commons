package net.ripe.rpki.commons.validation.properties;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import java.net.URI;

public class URIGen extends Generator<URI> {
    public final int HIER_AUTHORITY = 0;
    public final int HIER_PATH_ABSOLUTE = 1;
    public final int HIER_PATH_ROOTLESS = 2;
    public final int HIER_PATH_EMPTY = 3;

    public final int HOST_REG_NAME = 0;
    public final int HOST_IPV4 = 1;
    public final int HOST_IPV6 = 2;

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
        }

        return null;
    }

    private URI buildURI() throws Exception {
        String uri = hierPart() + query() + fragment();
        return new URI(uri);
    }

    private String scheme() {
        return randomString(1, 10) + "://";
    }

    private String hierPart() throws Exception {
        switch (r.nextInt(0, 3)) {
            case HIER_AUTHORITY: return scheme() + userinfo() + host() + port() + path();
            case HIER_PATH_ABSOLUTE: return "/" + randomString();
            case HIER_PATH_ROOTLESS: return randomString();
            case HIER_PATH_EMPTY: return "";
            default: throw new Exception("Invalid option for hierPart");
        }
    }

    private String path() {
        if (r.nextBoolean()) {
            return "";
        }

        return "/" + randomString(1,100);
    }

    private String userinfo() {
        if (r.nextBoolean()) {
            return "";
        }

        return randomString() + ":" + randomString() + "@";
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
        return randomString(1, 100);
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

    private String query() {
        if (r.nextBoolean()) {
            return "";
        }

        return "?" + randomString();
    }

    private String fragment() {
        if (r.nextBoolean()) {
            return "";
        }

        return "#" + randomString();
    }

    private String randomString() {
        return randomString( 0, 100);
    }

    private String randomString(int minLength, int maxLength) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < r.nextInt(minLength, maxLength); i++) {
            sb.append(r.nextChar('A', 'Z'));
        }

        return sb.toString();
    }

}
