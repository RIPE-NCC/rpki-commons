package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.TypePermission;

/**
 * XStream TypePermission that accepts all types that have been aliased.
 */
public class AliasedTypePermission implements TypePermission {
    private final XStream xStream;

    public AliasedTypePermission(XStream xStream) {
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
        return !xStream.getMapper().serializedClass(type).equals(type.getName());
    }
}
