package net.ripe.commons.provisioning.payload.common;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;
import net.ripe.commons.provisioning.serialization.CertificateUrlListConverter;
import net.ripe.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class CertificateElementConverter implements Converter {
    
    private static final String CERT_URL = "cert_url";
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == CertificateElement.class;
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        CertificateElement certificateElement = (CertificateElement) source;

        writer.addAttribute(CERT_URL, CertificateUrlListConverter.INSTANCE.toString(certificateElement.getIssuerCertificatePublicationUris()));
        encodeResources(writer, REQ_RESOURCE_SET_AS, certificateElement.getAllocatedAsn());
        encodeResources(writer, REQ_RESOURCE_SET_IPV4, certificateElement.getAllocatedIpv4());
        encodeResources(writer, REQ_RESOURCE_SET_IPV6, certificateElement.getAllocatedIpv6());
        context.convertAnother(certificateElement.getCertificate().getEncoded());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        CertificateElement certificateElement = new CertificateElement();

        String uriString = reader.getAttribute(CERT_URL);
        Validate.notNull(uriString, CERT_URL + " attribute is required");
        certificateElement.setIssuerCertificatePublicationLocation(CertificateUrlListConverter.INSTANCE.fromString(uriString));

        certificateElement.setAllocatedAsn(decodeResources(reader, REQ_RESOURCE_SET_AS));
        certificateElement.setAllocatedIpv4(decodeResources(reader, REQ_RESOURCE_SET_IPV4));
        certificateElement.setAllocatedIpv6(decodeResources(reader, REQ_RESOURCE_SET_IPV6));
        
        certificateElement.setCertificate(decodeCertificate(reader, context));

        return certificateElement;
    }

    private X509ResourceCertificate decodeCertificate(HierarchicalStreamReader reader, UnmarshallingContext context) {
        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[])context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("validationLocation", base64DecodedCertificate);
        return parser.getCertificate();
    }

    public static IpResourceSet decodeResources(HierarchicalStreamReader reader, String attribute) {
        String resources = reader.getAttribute(attribute);
        if (StringUtils.isBlank(resources)) {
            return null;
        } else {
            return IpResourceSetProvisioningConverter.INSTANCE.fromString(resources);
        } 
    }

    public static void encodeResources(HierarchicalStreamWriter writer, String attribute, IpResourceSet resources) {
        if (resources != null && !resources.isEmpty()) {
            writer.addAttribute(attribute, IpResourceSetProvisioningConverter.INSTANCE.toString(resources));
        }
    }
}
