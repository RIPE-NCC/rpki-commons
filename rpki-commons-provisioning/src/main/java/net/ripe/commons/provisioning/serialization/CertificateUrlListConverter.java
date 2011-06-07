package net.ripe.commons.provisioning.serialization;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;

public class CertificateUrlListConverter extends AbstractSingleValueConverter {

    public static final CertificateUrlListConverter INSTANCE = new CertificateUrlListConverter();
    
    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == List.class;
    }

    @Override
    public List<URI> fromString(String str) {
        List<URI> result = new ArrayList<URI>();
        for (String uri: str.split(",")) {
            result.add(URI.create(uri));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    @Override
    public String toString(Object obj) {
        if (obj == null)
            return null;
        List<String> encodedUrls = new ArrayList<String>();
        for (URI uri: (List<URI>) obj) {
            encodedUrls.add(uri.toString().replace(",", "%2C"));
        }
        return StringUtils.join(encodedUrls, ",");
    }
}
