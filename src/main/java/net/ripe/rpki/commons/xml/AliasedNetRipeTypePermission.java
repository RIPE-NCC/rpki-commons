package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.TypePermission;

/**
 * XStream TypePermission that accepts all types that have been aliased that are from net.ripe.
 *
 * Prevents types for which a default alias exists, that are not on the allow-list, and not from net.ripe.
 * to be de-serialised. Further limits the amount of classes that are available to be used as gadgets.
 */
public class AliasedNetRipeTypePermission implements TypePermission {
    private final XStream xStream;

    public AliasedNetRipeTypePermission(XStream xStream) {
        this.xStream = xStream;
    }

    /**
     * Allow types that have an alias by checking whether their serialized name differs from their
     * fully qualified name.
     *
     * @param type type to check
     * @return whether an alias has been applied to the type
     */
    @Override
    public boolean allows(Class type) {
        return type.getName().startsWith("net.ripe.") && !type.getName().equals(xStream.getMapper().serializedClass(type));
    }
}
