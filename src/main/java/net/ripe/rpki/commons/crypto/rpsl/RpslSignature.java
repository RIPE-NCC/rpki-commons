package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.collect.FluentIterable;
import com.google.common.collect.Maps;
import org.bouncycastle.util.encoders.Base64;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class RpslSignature {
    public static final String SIGNATURE_VERSION = "rpkiv1";

    private final LinkedHashMap<String, String> signatureValues;
    private List<String> signedAttributes;

    private RpslSignature(LinkedHashMap<String, String> signatureValues) {
        Preconditions.checkArgument(signatureValues.containsKey("v"),
                "Missing mandatory version ('v') attribute in signature");
//        Preconditions.checkArgument(SIGNATURE_VERSION.equals(signatureValues.get("v")),
//                "Signature version expected to be " + SIGNATURE_VERSION);

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

    public static RpslSignature parse(String input) {
        LinkedHashMap<String, String> attributes = Maps.newLinkedHashMap();
        for (String attribute : Splitter.on(';').trimResults().split(input)) {
            if (attribute.indexOf('=') != 1) throw new IllegalArgumentException("Wrong format in "+ attribute);
            String key = attribute.substring(0, 1);
            String value = attribute.substring(2);
            if (attributes.put(key, value) != null) throw new IllegalArgumentException("Multiple attributes are not allowed");
        }
        return new RpslSignature(attributes);
    }

    public String getValue(String name) {
        return signatureValues.get(name);
    }

    public List<String> getSignedAttributes() {
        return signedAttributes;
    }

    public String canonicalise() {
        FluentIterable<String> attributes = FluentIterable.from(signatureValues.entrySet())
                .transform(new Function<Map.Entry<String, String>, String>() {
                    public String apply(Map.Entry<String, String> input) {
                        return input.getKey() + "="
                                + (input.getKey().equals("b") ? "" : input.getValue());
                    }
                });
        return Joiner.on("; ").join(attributes).concat("\n");
    }

    public byte[] getSignatureValue() {
        String data = signatureValues.get("b");
        return Base64.decode(data);
    }

    public URI getCertificateUri() {
        return URI.create(signatureValues.get("c"));
    }

    public String getSignatureMethod() {
        return signatureValues.get("m");
    }
}
