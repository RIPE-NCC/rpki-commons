package net.ripe.commons.provisioning.payload.error;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

/**
 * Needed to force adding the 'xml:lang="en-US"' to description elements
 */
public class DescriptionElementConverter implements Converter {

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class clazz) {
        return clazz.equals(String.class);
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        String description = (String) source;
        writer.addAttribute("xml:lang", "en-US");
        writer.setValue(description);
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        return reader.getValue();
    }
    
}
