package net.ripe.rpki.commons.util;

import lombok.Getter;

import java.util.Arrays;

public enum RepositoryObjectType {

    Manifest("mft"),
    Roa("roa"),
    Certificate("cer"),
    Crl("crl"),
    Gbr("gbr"),
    Aspa("asa"),
    Unknown("unknown");

    @Getter
    private final String fileExtension;

    RepositoryObjectType(String fileExtension) {
        this.fileExtension = fileExtension;
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
