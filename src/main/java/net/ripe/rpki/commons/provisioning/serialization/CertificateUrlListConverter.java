package net.ripe.rpki.commons.provisioning.serialization;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class CertificateUrlListConverter extends AbstractSingleValueConverter {

    public static final CertificateUrlListConverter INSTANCE = new CertificateUrlListConverter();

    @Override
    public boolean canConvert(Class type) {
        return type == List.class;
    }

    @Override
    public List<URI> fromString(String str) {
        List<URI> result = new ArrayList<>();
        for (String uri : str.split(",")) {
            result.add(URI.create(uri));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    @Override
    public String toString(Object obj) {
        if (obj == null) {
            return null;
        }
        List<String> encodedUrls = new ArrayList<>();
        for (URI uri : (List<URI>) obj) {
            encodedUrls.add(uri.toString().replace(",", "%2C"));
        }
        return String.join(",", encodedUrls);
    }
}
