package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;

public class ManifestCmsConverter implements Converter {

    @Override
    public boolean canConvert(Class type) {
        return ManifestCms.class.equals(type);
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        ManifestCms manifest = (ManifestCms) source;
        writer.startNode("encoded");
        context.convertAnother(manifest.getEncoded());
        writer.endNode();
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        reader.moveDown();
        Validate.isTrue("encoded".equals(reader.getNodeName()));
        byte[] encoded = (byte[]) context.convertAnother(null, byte[].class);
        reader.moveUp();
        ManifestCmsParser parser = new ManifestCmsParser();
        parser.parse(ValidationResult.withLocation("unknown.mft"), encoded);
        return parser.getManifestCms();
    }
}
