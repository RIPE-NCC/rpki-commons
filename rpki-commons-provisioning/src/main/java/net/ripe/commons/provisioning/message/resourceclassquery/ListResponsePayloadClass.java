package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import net.ripe.commons.provisioning.message.ProvisioningPayloadClass;
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

    private String resourceSetAs;
    private String resourceSetIpv4;
    private String resourceSetIpv6;
    private DateTime resourceSetNotAfter;
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
        StringBuilder builder = new StringBuilder();

        boolean isFirst = true;

        for (URI uri : certificateAuthorityUri) {

            if (!isFirst) {
                builder.append(",");
            }

            builder.append(uri.toString());

            isFirst = false;
        }

        this.certificateUrl = builder.toString();
        return this;
    }

    public String getResourceSetAs() {
        return resourceSetAs;
    }

    public String getResourceSetIpv4() {
        return resourceSetIpv4;
    }

    public String getResourceSetIpv6() {
        return resourceSetIpv6;
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


    void setResourceSetAs(String resourceSetAs) {
        this.resourceSetAs = resourceSetAs;
    }

    void setResourceSetIpv4(String resourceSetIpv4) {
        this.resourceSetIpv4 = resourceSetIpv4;
    }

    void setResourceSetIpv6(String resourceSetIpv6) {
        this.resourceSetIpv6 = resourceSetIpv6;
    }

    void setResourceSetNotAfter(DateTime resourceSetNotAfter) {
        this.resourceSetNotAfter = resourceSetNotAfter;
    }

    void setSuggestedSiaHeadUri(String suggestedSiaHeadUri) {
        this.suggestedSiaHeadUri = suggestedSiaHeadUri;
    }

}
