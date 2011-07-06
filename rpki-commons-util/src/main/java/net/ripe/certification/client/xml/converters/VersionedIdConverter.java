package net.ripe.certification.client.xml.converters;

import net.ripe.commons.certification.util.VersionedId;

import com.thoughtworks.xstream.converters.SingleValueConverter;

/**
 * Handles old id consisting of just a "long" (without version) for backwards
 * compatibility.
 */
public class VersionedIdConverter implements SingleValueConverter {

	@SuppressWarnings("rawtypes")
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