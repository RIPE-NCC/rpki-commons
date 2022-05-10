package net.ripe.rpki.commons.util;

import lombok.Getter;

public enum RepositoryObjectType {

    Manifest("mft"),
    Roa("roa"),
    Certificate("cer"),
    Crl("crl"),
    Gbr("gbr"),
    Aspa("asa"),
    Unknown("unknown");

    @Getter
    private final String typeName;

    RepositoryObjectType(String typeName) {
        this.typeName = typeName;
    }

    /**
     * See https://www.iana.org/assignments/rpki/rpki.xhtml for the list of registered RPKI file extensions
     */
    public static RepositoryObjectType parse(String name) {
        if (name.endsWith(".mft")) {
            return Manifest;
        }
        if (name.endsWith(".crl")) {
            return Crl;
        }
        if (name.endsWith(".cer")) {
            return Certificate;
        }
        if (name.endsWith(".roa")) {
            return Roa;
        }
        if (name.endsWith(".gbr")) {
            return Gbr;
        }
        if (name.endsWith(".asa")) {
            return Aspa;
        }
        return Unknown;
    }
}
