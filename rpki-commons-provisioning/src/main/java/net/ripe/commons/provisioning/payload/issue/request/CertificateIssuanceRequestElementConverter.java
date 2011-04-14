package net.ripe.commons.provisioning.payload.issue.request;

import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class CertificateIssuanceRequestElementConverter implements Converter {

    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";
    private static final String CLASS_NAME = "class_name";

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        CertificateIssuanceRequestElement content = (CertificateIssuanceRequestElement) source;

        writer.addAttribute(CLASS_NAME, content.getClassName());

        if (content.getAllocatedAsn() != null) {
            String asnString = stripASandSpaces(content.getAllocatedAsn().toString());
            writer.addAttribute(REQ_RESOURCE_SET_AS, asnString);
        }

        if (content.getAllocatedIpv4() != null) {
            String ipv4String = stripASandSpaces(content.getAllocatedIpv4().toString());
            writer.addAttribute(REQ_RESOURCE_SET_IPV4, ipv4String);
        }

        if (content.getAllocatedIpv6() != null) {
            String ipv6String = stripASandSpaces(content.getAllocatedIpv6().toString());
            writer.addAttribute(REQ_RESOURCE_SET_IPV6, ipv6String);
        }

        context.convertAnother(content.getCertificateRequest().getEncoded());
    }

    private String stripASandSpaces(String string) {
        String asFilteredOut = StringUtils.replaceChars(string, "AS", "");
        return StringUtils.replaceChars(asFilteredOut, " ", "");
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        CertificateIssuanceRequestElement content = new CertificateIssuanceRequestElement();

        String className = reader.getAttribute(CLASS_NAME);
        Validate.notNull(className, "class_name attribute is required");
        content.setClassName(className);

        String resourceSetAsNumbers = reader.getAttribute(REQ_RESOURCE_SET_AS);
        if (StringUtils.isNotBlank(resourceSetAsNumbers)) {
            content.setAllocatedAsn(IpResourceSet.parse(resourceSetAsNumbers));
        }

        String allocatedIpv4 = reader.getAttribute(REQ_RESOURCE_SET_IPV4);
        if (StringUtils.isNotBlank(allocatedIpv4)) {
            content.setAllocatedIpv4(IpResourceSet.parse(allocatedIpv4));
        }

        String allocatedIpv6 = reader.getAttribute(REQ_RESOURCE_SET_IPV6);
        if (StringUtils.isNotBlank(allocatedIpv6)) {
            content.setAllocatedIpv6(IpResourceSet.parse(allocatedIpv6));
        }

        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[]) context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(base64DecodedCertificate);
        content.setCertificateRequest(certificationRequest);

        return content;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return type == CertificateIssuanceRequestElement.class;
    }
}
