package net.ripe.commons.provisioning.payload.issue.request;

import static net.ripe.commons.provisioning.payload.common.CertificateElementConverter.*;

import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class CertificateIssuanceRequestElementConverter implements Converter {

    private static final String CLASS_NAME = "class_name";
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == CertificateIssuanceRequestElement.class;
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        CertificateIssuanceRequestElement content = (CertificateIssuanceRequestElement) source;

        writer.addAttribute(CLASS_NAME, content.getClassName());
        encodeResources(writer, REQ_RESOURCE_SET_AS, content.getAllocatedAsn());
        encodeResources(writer, REQ_RESOURCE_SET_IPV4, content.getAllocatedIpv4());
        encodeResources(writer, REQ_RESOURCE_SET_IPV6, content.getAllocatedIpv6());
        context.convertAnother(content.getCertificateRequest().getEncoded());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        CertificateIssuanceRequestElement content = new CertificateIssuanceRequestElement();

        String className = reader.getAttribute(CLASS_NAME);
        Validate.notNull(className, "class_name attribute is required");
        content.setClassName(className);

        content.setAllocatedAsn(decodeResources(reader, REQ_RESOURCE_SET_AS));
        content.setAllocatedIpv4(decodeResources(reader, REQ_RESOURCE_SET_IPV4));
        content.setAllocatedIpv6(decodeResources(reader, REQ_RESOURCE_SET_IPV6));

        content.setCertificateRequest(decodeCertificateRequest(reader, context));

        return content;
    }

    private PKCS10CertificationRequest decodeCertificateRequest(HierarchicalStreamReader reader, UnmarshallingContext context) {
        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[]) context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        return new PKCS10CertificationRequest(base64DecodedCertificate);
    }

}
