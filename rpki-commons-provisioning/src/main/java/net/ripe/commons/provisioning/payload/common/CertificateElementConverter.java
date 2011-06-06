package net.ripe.commons.provisioning.payload.common;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

import com.thoughtworks.xstream.converters.*;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class CertificateElementConverter implements Converter {
    
    private static final String CERT_URL = "cert_url";
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        CertificateElement certificateElement = (CertificateElement) source;

        String urisString = StringUtils.join(certificateElement.getIssuerCertificatePublicationUris(), ",");
        writer.addAttribute(CERT_URL, urisString);

        if (certificateElement.getAllocatedAsn() != null) {
            String asnsString = certificateElement.getAllocatedAsn().toString();
            asnsString = StringUtils.replaceChars(asnsString, "AS", "");
            asnsString = StringUtils.replaceChars(asnsString, " ", "");
            writer.addAttribute(REQ_RESOURCE_SET_AS, asnsString);
        }

        if (certificateElement.getAllocatedIpv4() != null) {
            String ipv4String = certificateElement.getAllocatedIpv4().toString();
            ipv4String = StringUtils.replaceChars(ipv4String, " ", "");
            writer.addAttribute(REQ_RESOURCE_SET_IPV4, ipv4String);
        }

        if (certificateElement.getAllocatedIpv6() != null) {
            String ipv6String = certificateElement.getAllocatedIpv6().toString();
            ipv6String = StringUtils.replaceChars(ipv6String, " ", "");
            writer.addAttribute(REQ_RESOURCE_SET_IPV6, ipv6String);
        }

        context.convertAnother(certificateElement.getCertificate().getEncoded());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        CertificateElement certificateElement = new CertificateElement();

        String uriString = reader.getAttribute(CERT_URL);
        Validate.notNull(uriString, CERT_URL + " attribute is required");
        
        List<URI> uris = new ArrayList<URI>();
        // FIXME we currently have a bug here on the split (CA name contains comma)
        for (String uri :uriString.split(",")) {
            uris.add(URI.create(uri));
        }
        
        certificateElement.setIssuerCertificatePublicationLocation(uris);

        IpResourceSet ipResourceSet = new IpResourceSet();
        
        String resourceSetAsNumbers = reader.getAttribute(REQ_RESOURCE_SET_AS);
        if (StringUtils.isNotBlank(resourceSetAsNumbers)) {
            ipResourceSet.addAll(IpResourceSet.parse(resourceSetAsNumbers));
        }

        String allocatedIpv4 = reader.getAttribute(REQ_RESOURCE_SET_IPV4);
        if (StringUtils.isNotBlank(allocatedIpv4)) {
            ipResourceSet.addAll(IpResourceSet.parse(allocatedIpv4));
        }

        String allocatedIpv6 = reader.getAttribute(REQ_RESOURCE_SET_IPV6);
        if (StringUtils.isNotBlank(allocatedIpv6)) {
            ipResourceSet.addAll(IpResourceSet.parse(allocatedIpv6));
        }
        
        certificateElement.setIpResourceSet(ipResourceSet);

        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[])context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("validationLocation", base64DecodedCertificate);
        certificateElement.setCertificate(parser.getCertificate());

        return certificateElement;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return type == CertificateElement.class;
    }
}
