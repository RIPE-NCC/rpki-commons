package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.base.CharMatcher;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RpslObject {

    private final String rpsl;

    private final Map<String, String> attributeValues = new HashMap<String, String>();

    private static final Pattern rpslKeyValuePattern = Pattern.compile("([^:]+):\\s*(.*\\S)\\s*");

    private static Map<String, List<String>> mandatoryAttributes = new HashMap<String, List<String>>(6);
    private static Map<String, List<String>> inrAttributes = new HashMap<String, List<String>>(6);

    static {
        Security.addProvider(new BouncyCastleProvider());

        mandatoryAttributes.put("as-block",  Arrays.asList("as-block", "org", "signature"));
        mandatoryAttributes.put("aut-num",   Arrays.asList("aut-num","as-name","member-of","import","mp-import","export","mp-export","default","mp-default","signature"));
        mandatoryAttributes.put("inetnum",   Arrays.asList("inetnum","netname","country","org","status","signature"));
        mandatoryAttributes.put("inet6num",  Arrays.asList("inet6num","netname","country","org","status","signature"));
        mandatoryAttributes.put("route",     Arrays.asList("route","origin","holes","org","member-of","signature"));
        mandatoryAttributes.put("as-route6", Arrays.asList("route6","origin","holes","org","member-of","signature"));

        inrAttributes.put("as-block", Collections.singletonList("as-block"));
        inrAttributes.put("aut-num",  Collections.singletonList("aut-num"));
        inrAttributes.put("inetnum",  Collections.singletonList("inetnum"));
        inrAttributes.put("inet6num", Collections.singletonList("inet6num"));
        inrAttributes.put("route",     Arrays.asList("route","origin"));
        inrAttributes.put("as-route6", Arrays.asList("route6","origin"));
    }

    private RpkiRpslSignature rpkiSignature;
    private String objectType;

    public RpslObject(String rpsl) {
        this.rpsl = rpsl;

        for (String line : rpsl.split("\n")) {
            line = line.trim();
            if (!line.startsWith("%") && !line.isEmpty()) {
                Matcher m = rpslKeyValuePattern.matcher(line);
                if(m.matches() && m.groupCount() == 2) {
                    String key = m.group(1);
                    String val = m.group(2);

                    if (objectType == null) {
                        objectType = key;
                    }

                    if (!attributeValues.containsKey(key)) {
                        attributeValues.put(key, val);
                    } else {
                        attributeValues.put(key, attributeValues.get(key) + "\n" + val);
                    }
                }
            }
        }
        parseRpkiSignature();
    }

    private void parseRpkiSignature() {
        String signatureString = getAttribute("signature");
        if (signatureString == null) return;
        rpkiSignature = RpkiRpslSignature.parse(signatureString);
    }

    public URI getRpkiSigningCertificateUri() {
        return rpkiSignature.getCertificateUri();
    }

    public String getRpsl() {
        return rpsl;
    }

    public Set<String> getAttributes() {
        return attributeValues.keySet();
    }

    public String getAttribute(String name) {
        return attributeValues.get(name);
    }

    public String canonicaliseAttributes(Iterable<String> signedAttributes) {
        return Joiner.on('\n').join(
                Iterables.transform(signedAttributes, canonicaliseAttribute()))
                + '\n';
    }

//    public boolean validateResourcesWithSigningCertificate() {
//        if (rpkiSignature == null) return false;
//
//
//
//    }

    public boolean validateSignature(PublicKey publicKey) throws NoSuchProviderException, NoSuchAlgorithmException {
        if (rpkiSignature == null) return false;

        byte[] signatureValue = rpkiSignature.getSignatureValue();

        String canonicalised = canonicaliseAttributes(rpkiSignature.getSignedAttributes())
                + "signature: " + rpkiSignature.canonicalise();

        Signature instance = Signature.getInstance(rpkiSignature.getSignatureMethod(), BouncyCastleProvider.PROVIDER_NAME);
        try {
            instance.initVerify(publicKey);
            instance.update(canonicalised.getBytes());
            return instance.verify(signatureValue);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private Function<String, String> canonicaliseAttribute() {
        return new Function<String, String>() {
            @Override
            public String apply(String input) {
                Preconditions.checkNotNull(input);
                return input.toLowerCase() + ": " + canonicaliseValue(attributeValues.get(input));
            }
        };
    }

    private String canonicaliseValue(String input) {
        return CharMatcher.WHITESPACE.trimAndCollapseFrom(input, ' ');
    }
}
