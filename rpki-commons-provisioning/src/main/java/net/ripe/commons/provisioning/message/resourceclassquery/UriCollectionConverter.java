package net.ripe.commons.provisioning.message.resourceclassquery;


import java.net.URI;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class UriCollectionConverter implements Converter {

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        URI[] uris = (URI[])source;

        StringBuilder builder = new StringBuilder();

        boolean isFirst = true;

        for (URI uri : uris) {

            if (!isFirst) {
                builder.append(",");
            }

            builder.append(uri.toString());

            isFirst = false;
        }

        writer.setValue(builder.toString());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == URI[].class;
    }
}
