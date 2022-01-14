package net.ripe.rpki.commons.util;

public enum RepositoryObjectType {

    Manifest, Roa, Certificate, Crl, Gbr, Unknown;

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
        return Unknown;
    }
}
