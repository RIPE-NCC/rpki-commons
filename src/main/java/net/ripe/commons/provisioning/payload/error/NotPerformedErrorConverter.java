package net.ripe.commons.provisioning.payload.error;

import org.apache.commons.lang.Validate;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class NotPerformedErrorConverter implements Converter {
    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        NotPerformedError error = (NotPerformedError)source;

        context.convertAnother(error.getErrorCode());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        String value = reader.getValue();

        Validate.notNull(value, "error code is required");

        int errorCode = Integer.parseInt(value);

        return NotPerformedError.getError(errorCode);
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return type == NotPerformedError.class;
    }
}
