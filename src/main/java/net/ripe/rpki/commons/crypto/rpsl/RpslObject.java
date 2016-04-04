package net.ripe.rpki.commons.crypto.rpsl;

import java.util.HashMap;
import java.util.List;
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
}
