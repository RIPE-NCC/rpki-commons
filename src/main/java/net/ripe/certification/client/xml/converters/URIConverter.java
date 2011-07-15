package net.ripe.certification.client.xml.converters;

import java.net.URI;

import org.apache.commons.lang.StringUtils;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;

public class URIConverter extends AbstractSingleValueConverter {

	@SuppressWarnings("rawtypes") 
    public boolean canConvert(Class type) {
        return type.equals(URI.class);
    }

    public Object fromString(String str) {
    	if (StringUtils.isEmpty(str)) {
    		return null;
    	} else {
    		return URI.create(str);
    	}
    }
}