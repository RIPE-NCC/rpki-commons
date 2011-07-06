package net.ripe.commons.provisioning.payload.common;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class X509ResourceCertificateBase64Converter implements Converter {

	@SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return type == X509ResourceCertificate.class;
    }

	@Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        X509ResourceCertificate certificate = (X509ResourceCertificate) source;
        context.convertAnother(certificate.getEncoded());
    }

	@Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        String base64Encoded = reader.getValue();

        byte[] decodedBytes = (byte[])context.convertAnother(base64Encoded.getBytes(), byte[].class);

        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("/tmp", decodedBytes);

        return parser.getCertificate();
    }
}