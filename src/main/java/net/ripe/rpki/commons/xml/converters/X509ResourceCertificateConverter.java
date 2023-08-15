package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;

public class X509ResourceCertificateConverter implements Converter {

    @Override
    public boolean canConvert(Class type) {
        return X509ResourceCertificate.class.equals(type);
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        X509ResourceCertificate certificate = (X509ResourceCertificate) source;
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
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse(ValidationResult.withLocation("unknown.cer"), encoded);
        return parser.getCertificate();
    }
}
