package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.SingleValueConverter;
import net.ripe.rpki.commons.util.VersionedId;

/**
 * Handles old id consisting of just a "long" (without version) for backwards
 * compatibility.
 */
public class VersionedIdConverter implements SingleValueConverter {

    @Override
    public boolean canConvert(Class type) {
        return VersionedId.class.equals(type);
    }

    @Override
    public Object fromString(String str) {
        return VersionedId.parse(str);
    }

    @Override
    public String toString(Object obj) {
        return obj.toString();
    }
}
