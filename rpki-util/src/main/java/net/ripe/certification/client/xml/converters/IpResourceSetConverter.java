package net.ripe.certification.client.xml.converters;

import net.ripe.ipresource.IpResourceSet;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;

public class IpResourceSetConverter extends AbstractSingleValueConverter {

	@SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return IpResourceSet.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return IpResourceSet.parse(s);
    }
}