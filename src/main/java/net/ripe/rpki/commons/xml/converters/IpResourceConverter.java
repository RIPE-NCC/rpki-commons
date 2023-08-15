package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;
import net.ripe.ipresource.IpResource;

public class IpResourceConverter extends AbstractSingleValueConverter {

    @Override
    public boolean canConvert(Class type) {
        return IpResource.class.isAssignableFrom(type);
    }

    @Override
    public Object fromString(String s) {
        return IpResource.parse(s);
    }
}
