package net.ripe.rpki.commons.util;

import lombok.Getter;

import java.util.Arrays;

public enum RepositoryObjectType {
    Certificate("cer", false),
    Crl("crl", false),
    Aspa("asa", true),
    Gbr("gbr", true),
    Manifest("mft", true),
    Roa("roa", true),
    SignedChecklist("sig", true),
    TrustAnchorKey("tak", true),
    Unknown("unknown", false);

    @Getter
    private final boolean isCmsBased;

    @Getter
    private final String fileExtension;

    RepositoryObjectType(String fileExtension, boolean isCmsBased) {
        this.fileExtension = fileExtension;
        this.isCmsBased = isCmsBased;
    }

    /**
     * See https://www.iana.org/assignments/rpki/rpki.xhtml for the list of registered RPKI file extensions
     */
    public static RepositoryObjectType parse(String name) {
        return Arrays.stream(RepositoryObjectType.values())
            .filter(t -> name.endsWith("." + t.getFileExtension()))
            .findFirst()
            .orElse(Unknown);
    }
}