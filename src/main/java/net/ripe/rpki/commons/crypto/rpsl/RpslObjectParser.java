package net.ripe.rpki.commons.crypto.rpsl;

import net.ripe.rpki.commons.validation.ValidationResult;

public class RpslObjectParser {

    private RpslObject rpslObject;

    public void parse(ValidationResult result, String rpsl) {
        rpslObject = new RpslObject(rpsl);
    }

    public RpslObject getRpslObject() {
        return rpslObject;
    }
}
