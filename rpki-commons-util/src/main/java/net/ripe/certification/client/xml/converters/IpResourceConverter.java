package net.ripe.certification.client.xml.converters;

import net.ripe.ipresource.IpResource;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;

public class IpResourceConverter extends AbstractSingleValueConverter {

	@SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return IpResource.class.isAssignableFrom(type);
    }

    @Override
    public Object fromString(String s) {
        return IpResource.parse(s);
    }
}