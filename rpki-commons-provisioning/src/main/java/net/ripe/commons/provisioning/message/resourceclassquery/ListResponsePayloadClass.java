package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import net.ripe.commons.provisioning.message.ProvisioningPayloadClass;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;

import java.net.URI;
import java.net.URISyntaxException;

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

    public String getClassName() {
        return className;
    }

    public URI[] getCertificateAuthorityUri() {
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

        return toIpRange(ipV4);
    }

    public IpRange[] getResourceSetIpv6() {
        String[] ipV6 = resourceSetIpv6.split(",");

        return toIpRange(ipV6);
    }

    private IpRange[] toIpRange(String[] ipV4) {
        int index = 0;
        IpRange[] ranges = new IpRange[ipV4.length];

        for (String ip : ipV4) {
            ranges[index++]= IpRange.parse(ip);
        }

        return ranges;
    }

    public DateTime getResourceSetNotAfter() {
        return resourceSetNotAfter;
    }

    public String getSuggestedSiaHeadUri() {
        return suggestedSiaHeadUri;
    }

    ListResponsePayloadClass setClassName(String className) {
        this.className = className;
        return this;
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

}
