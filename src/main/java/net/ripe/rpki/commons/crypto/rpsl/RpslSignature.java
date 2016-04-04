package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;

import java.util.List;
import java.util.Map;

public class RpslSignature {
    public static final String SIGNATURE_VERSION = "rpkiv1";

    private final Map<String, String> signatureValues;
    private List<String> signedAttributes;

    private RpslSignature(Map<String, String> signatureValues) {
        Preconditions.checkArgument(signatureValues.containsKey("v"),
                "Missing mandatory version ('v') attribute in signature");
        Preconditions.checkArgument(SIGNATURE_VERSION.equals(signatureValues.get("v")),
                "Signature version expected to be " + SIGNATURE_VERSION);

        Preconditions.checkArgument(signatureValues.containsKey("c"),
                "Missing mandatory certificate ('c') attribute in signature");

        Preconditions.checkArgument(signatureValues.containsKey("m"),
                "Missing mandatory signature method ('m') attribute in signature");

        Preconditions.checkArgument(signatureValues.containsKey("t"),
                "Missing mandatory signature time ('t') attribute in signature");

        Preconditions.checkArgument(signatureValues.containsKey("a"),
                "Missing mandatory signed attributes ('a') attribute in signature");
        parseSignedAttributes(signatureValues.get("a"));

        Preconditions.checkArgument(signatureValues.containsKey("b"),
                "Missing mandatory signature ('b') attribute in signature");

        this.signatureValues = signatureValues;
    }

    private void parseSignedAttributes(String value) {
        signedAttributes = Splitter.on("+").splitToList(value);
    }

    public static RpslSignature parse(String string) {
        Map<String, String> signatureValues = Splitter.on(';')
                .omitEmptyStrings()
                .trimResults()
                .withKeyValueSeparator('=')
                .split(string);
        return new RpslSignature(signatureValues);
    }

    public String getValue(String name) {
        return signatureValues.get(name);
    }

    public List<String> getSignedAttributes() {
        return signedAttributes;
    }
}
