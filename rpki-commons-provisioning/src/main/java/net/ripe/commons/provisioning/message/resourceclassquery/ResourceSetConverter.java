package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import org.apache.commons.lang.StringUtils;

public class ResourceSetConverter implements Converter {
    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        ResourceSet set = (ResourceSet) source;

        writer.addAttribute("cert_url", StringUtils.join(set.getIssuerCertificatePublicationLocation(), ","));

        if (set.getResourceSetAsNumbers() != null) {
            writer.addAttribute("req_resource_set_as", StringUtils.join(set.getResourceSetAsNumbers(), ","));
        }

        if (set.getResourceSetIpv4() != null) {
            writer.addAttribute("req_resource_set_ipv4", StringUtils.join(set.getResourceSetIpv4(), ","));
        }

        if (set.getResourceSetIpv6() != null) {
            writer.addAttribute("req_resource_set_ipv6", StringUtils.join(set.getResourceSetIpv6(), ","));
        }

        context.convertAnother(ResourceClassUtil.encodeCertificate(set.getCertificate()));
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

        //
        return null;
    }

    @Override
    public boolean canConvert(Class type) {
        return type == ResourceSet.class;
    }
}
