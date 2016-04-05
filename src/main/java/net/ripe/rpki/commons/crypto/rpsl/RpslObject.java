package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.base.CharMatcher;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RpslObject {

    private String rpsl;

    private Map<String, String> attributeValues = new HashMap<String, String>();

    private static final Pattern rpslKeyValuePattern = Pattern.compile("([^:]+):\\s*(.*\\S)\\s*");

    public RpslObject(String rpsl) {
        this.rpsl = rpsl;

        for (String line : rpsl.split("\n")) {
            line = line.trim();
            if (!line.startsWith("%") && !line.isEmpty()) {
                Matcher m = rpslKeyValuePattern.matcher(line);
                if(m.matches() && m.groupCount() == 2) {
                    String key = m.group(1);
                    String val = m.group(2);

                    if (attributeValues.containsKey(key)) {
                        attributeValues.put(key, val);
                    } else {
                        attributeValues.put(key, attributeValues.get(key) + "\n" + val);
                    }
                }

            }

        }

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
