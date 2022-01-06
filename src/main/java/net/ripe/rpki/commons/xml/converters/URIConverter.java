package net.ripe.rpki.commons.xml.converters;

import com.google.common.base.Strings;
import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;

import java.net.URI;


public class URIConverter extends AbstractSingleValueConverter {

    @Override
    @SuppressWarnings("rawtypes")
    public boolean canConvert(Class type) {
        return type.equals(URI.class);
    }

    @Override
    public Object fromString(String str) {
        if (Strings.isNullOrEmpty(str)) {
            return null;
        } else {
            return URI.create(str);
        }
    }
}
