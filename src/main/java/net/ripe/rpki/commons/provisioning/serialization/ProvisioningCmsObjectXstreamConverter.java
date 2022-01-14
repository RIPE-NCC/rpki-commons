package net.ripe.rpki.commons.provisioning.serialization;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectParser;
import org.apache.commons.lang3.Validate;

/**
 * A converter to be used when (de)serializing a ProvisioningCmsObject to/from xml using XStream.
 *
 * @see net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
 */
public class ProvisioningCmsObjectXstreamConverter implements Converter {

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return ProvisioningCmsObject.class.equals(type);
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        ProvisioningCmsObject cmsObject = (ProvisioningCmsObject) source;
        writer.startNode("encoded");
        context.convertAnother(cmsObject.getEncoded());
        writer.endNode();
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        reader.moveDown();
        Validate.isTrue("encoded".equals(reader.getNodeName()));
        byte[] encoded = (byte[]) context.convertAnother(null, byte[].class);
        reader.moveUp();
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        return parser.getProvisioningCmsObject();
    }

}
