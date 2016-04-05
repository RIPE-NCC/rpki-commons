package net.ripe.rpki.commons.crypto.rpsl;

import net.ripe.rpki.commons.validation.ValidationResult;

public class RpslObjectParser {

    private RpslObject rpslObject;

    public void parse(ValidationResult result, String rpsl) {
        rpslObject = new RpslObject(rpsl);
        String signatureString = rpslObject.getAttribute("signature");
        if (signatureString != null) {
            RpslSignature signature = RpslSignature.parse(signatureString);

            String canonicalised = rpslObject.canonicaliseAttributes(signature.getSignedAttributes())
                    + RpslSignature.stripSignatureValue(signatureString);
        }
    }

    public RpslObject getRpslObject() {
        return rpslObject;
    }
}
