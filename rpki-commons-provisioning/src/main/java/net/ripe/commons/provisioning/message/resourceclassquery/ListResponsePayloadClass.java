package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import com.thoughtworks.xstream.annotations.XStreamImplicit;
import net.ripe.commons.provisioning.message.ProvisioningPayloadClass;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.joda.time.DateTime;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@XStreamAlias("class")
public class ListResponsePayloadClass extends ProvisioningPayloadClass {
    @XStreamAsAttribute
    @XStreamAlias("class_name")
    private String className;

    @XStreamAlias("cert_url")
    @XStreamAsAttribute
    private String certificateUrl;

    @XStreamAlias("resource_set_as")
    @XStreamAsAttribute
    private String resourceSetAsNumbers = "";

    @XStreamAlias("resource_set_ipv4")
    @XStreamAsAttribute
    private String resourceSetIpv4 = "";

    @XStreamAlias("resource_set_ipv6")
    @XStreamAsAttribute
    private String resourceSetIpv6 = "";

    @XStreamAlias("resource_set_notafter")
    @XStreamAsAttribute
    private DateTime resourceSetNotAfter;

    @XStreamAlias("suggested_sia_head")
    @XStreamAsAttribute
    private String suggestedSiaHeadUri;

    @XStreamAlias("certificate")
    @XStreamImplicit(itemFieldName = "certificate")
    private List<ResourceSet> resourceSets;

    public String getClassName() {
        return className;
    }

    ListResponsePayloadClass setClassName(String className) {
        this.className = className;
        return this;
    }


    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

    public URI[] getCertificateAuthorityUri() {
        if (certificateUrl == null) {
            return null;
        }

        String[] urls = certificateUrl.split(",");

        URI[] uris = new URI[urls.length];

        int i = 0;
        for (String url : urls) {
            try {
                uris[i++] = new URI(url);
            } catch (URISyntaxException e) {
                // TODO handle
                e.printStackTrace();
            }
        }

        return uris;
    }

    ListResponsePayloadClass setCertificateAuthorityUri(URI[] certificateAuthorityUri) {
        this.certificateUrl = StringUtils.join(certificateAuthorityUri, ",");
        return this;
    }

    public IpRange[] getResourceSetIpv4() {
        String[] ipV4 = resourceSetIpv4.split(",");

        return ResourceClassUtil.toIpRange(ipV4);
    }

    public IpRange[] getResourceSetIpv6() {
        String[] ipV6 = resourceSetIpv6.split(",");

        return ResourceClassUtil.toIpRange(ipV6);
    }

    public DateTime getResourceSetNotAfter() {
        return resourceSetNotAfter;
    }

    public String getSuggestedSiaHeadUri() {
        return suggestedSiaHeadUri;
    }



    public String[] getResourceSetAsNumbers() {
        return resourceSetAsNumbers != null ? resourceSetAsNumbers.split(",") : null;
    }

    ListResponsePayloadClass setResourceSetAsNumbers(String... resourceSetAsNumbers) {
        if (resourceSetAsNumbers != null) {
            this.resourceSetAsNumbers = StringUtils.join(resourceSetAsNumbers, ",");
        }
        return this;
    }

    ListResponsePayloadClass setResourceSetIpv4(IpRange... resourceSetIpv4) {
        if (resourceSetIpv4 != null) {
            this.resourceSetIpv4 = StringUtils.join(resourceSetIpv4, ",");
        }

        return this;
    }

    ListResponsePayloadClass setResourceSetIpv6(IpRange... resourceSetIpv6) {
        if (resourceSetIpv6 != null) {
            this.resourceSetIpv6 = StringUtils.join(resourceSetIpv6, ",");
        }

        return this;
    }

    ListResponsePayloadClass setResourceSetNotAfter(DateTime resourceSetNotAfter) {
        this.resourceSetNotAfter = resourceSetNotAfter;
        return this;
    }

    ListResponsePayloadClass setSuggestedSiaHeadUri(String suggestedSiaHeadUri) {
        this.suggestedSiaHeadUri = suggestedSiaHeadUri;
        return this;
    }


    public List<ResourceSet> getResourceSets() {
        return resourceSets;
    }

    ListResponsePayloadClass setResourceSets(List<ResourceSet> resourceSets) {
        this.resourceSets = resourceSets;
        return this;
    }
}
