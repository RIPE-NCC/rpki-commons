package net.ripe.commons.provisioning.message.list.response;

import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class ResourceClassConverter implements Converter {
    private static final String CERT_URL = "cert_url";
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        ResourceClass set = (ResourceClass) source;

        writer.addAttribute(CERT_URL, StringUtils.join(set.getIssuerCertificatePublicationLocation(), ","));

        if (set.getAllocatedAsn() != null) {
            writer.addAttribute(REQ_RESOURCE_SET_AS, StringUtils.join(set.getAllocatedAsn(), ","));
        }

        if (set.getAllocatedIpv4() != null) {
            writer.addAttribute(REQ_RESOURCE_SET_IPV4, StringUtils.join(set.getAllocatedIpv4(), ","));
        }

        if (set.getAllocatedIpv6() != null) {
            writer.addAttribute(REQ_RESOURCE_SET_IPV6, StringUtils.join(set.getAllocatedIpv6(), ","));
        }

        context.convertAnother(set.getCertificate().getEncoded());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        ResourceClass set = new ResourceClass();

        String attribute = reader.getAttribute(CERT_URL);
        Validate.notNull(attribute, CERT_URL + " attribute is required");
        set.setIssuerCertificatePublicationLocation(attribute.split(","));

        String resourceSetAsNumbers = reader.getAttribute(REQ_RESOURCE_SET_AS);
        if (StringUtils.isNotBlank(resourceSetAsNumbers)) {
            set.setAllocatedAsn(resourceSetAsNumbers.split(","));
        }

        String allocatedIpv4 = reader.getAttribute(REQ_RESOURCE_SET_IPV4);
        if (StringUtils.isNotBlank(allocatedIpv4)) {
            set.setAllocatedIpv4(allocatedIpv4.split(","));
        }

        String allocatedIpv6 = reader.getAttribute(REQ_RESOURCE_SET_IPV6);
        if (StringUtils.isNotBlank(allocatedIpv6)) {
            set.setAllocatedIpv6(allocatedIpv6.split(","));
        }

        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[])context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("/tmp", base64DecodedCertificate);
        set.setCertificate(parser.getCertificate());

        return set;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return type == ResourceClass.class;
    }
}
