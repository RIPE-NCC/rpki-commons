package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;
import net.ripe.ipresource.IpResourceSet;

public class IpResourceSetConverter extends AbstractSingleValueConverter {

    @Override
    public boolean canConvert(Class type) {
        return IpResourceSet.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return IpResourceSet.parse(s);
    }
}
