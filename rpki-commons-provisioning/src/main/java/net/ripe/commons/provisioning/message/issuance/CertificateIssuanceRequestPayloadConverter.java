package net.ripe.commons.provisioning.message.issuance;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class CertificateIssuanceRequestPayloadConverter implements Converter {
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";
    private static final String CLASS_NAME = "class_name";

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        CertificateIssuanceRequestPayload content = (CertificateIssuanceRequestPayload) source;

        writer.addAttribute(CLASS_NAME, content.getClassName());

        if (content.getAllocatedAsn() != null) {
            writer.addAttribute(REQ_RESOURCE_SET_AS, StringUtils.join(content.getAllocatedAsn(), ","));
        }

        if (content.getAllocatedIpv4() != null) {
            writer.addAttribute(REQ_RESOURCE_SET_IPV4, StringUtils.join(content.getAllocatedIpv4(), ","));
        }

        if (content.getAllocatedIpv6() != null) {
            writer.addAttribute(REQ_RESOURCE_SET_IPV6, StringUtils.join(content.getAllocatedIpv6(), ","));
        }

        context.convertAnother(content.getCertificate().getEncoded());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        CertificateIssuanceRequestPayload content = new CertificateIssuanceRequestPayload();

        String className = reader.getAttribute(CLASS_NAME);
        Validate.notNull(className, "class_name attribute is required");
        content.setClassName(className);

        String resourceSetAsNumbers = reader.getAttribute(REQ_RESOURCE_SET_AS);
        if (StringUtils.isNotBlank(resourceSetAsNumbers)) {
            content.setAllocatedAsn(resourceSetAsNumbers.split(","));
        }

        String allocatedIpv4 = reader.getAttribute(REQ_RESOURCE_SET_IPV4);
        if (StringUtils.isNotBlank(allocatedIpv4)) {
            content.setAllocatedIpv4(allocatedIpv4.split(","));
        }

        String allocatedIpv6 = reader.getAttribute(REQ_RESOURCE_SET_IPV6);
        if (StringUtils.isNotBlank(allocatedIpv6)) {
            content.setAllocatedIpv6(allocatedIpv6.split(","));
        }

        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[])context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(base64DecodedCertificate);
        content.setCertificate(certificationRequest);

        return content;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return type == CertificateIssuanceRequestPayload.class;
    }
}
