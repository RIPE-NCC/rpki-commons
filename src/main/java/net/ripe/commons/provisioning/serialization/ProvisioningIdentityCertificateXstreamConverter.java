package net.ripe.commons.provisioning.serialization;

import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateParser;

import org.apache.commons.lang.Validate;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

/**
 * A converter to be used when (de)serializing a ProvisioningIdentityCertificate to/from xml using XStream.
 * @see ProvisioningIdentityCertificate
 */
public class ProvisioningIdentityCertificateXstreamConverter implements Converter {

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return ProvisioningIdentityCertificate.class.equals(type);
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        ProvisioningIdentityCertificate certificate = (ProvisioningIdentityCertificate) source;
        writer.startNode("encoded");
        context.convertAnother(certificate.getEncoded());
        writer.endNode();
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        reader.moveDown();
        Validate.isTrue("encoded".equals(reader.getNodeName()));
        byte[] encoded = (byte[]) context.convertAnother(null, byte[].class);
        reader.moveUp();
        ProvisioningIdentityCertificateParser parser = new ProvisioningIdentityCertificateParser();
        parser.parse("encoded", encoded);
        return parser.getCertificate();
    }

}
