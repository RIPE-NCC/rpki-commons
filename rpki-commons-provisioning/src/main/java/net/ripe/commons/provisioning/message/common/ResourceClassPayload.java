package net.ripe.commons.provisioning.message.common;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import com.thoughtworks.xstream.annotations.XStreamImplicit;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.joda.time.DateTime;

import java.util.ArrayList;
import java.util.List;

public class ResourceClassPayload {
    @XStreamAsAttribute
    @XStreamAlias("class_name")
    private String className;

    @XStreamAlias("cert_url")
    @XStreamAsAttribute
    private String certificateAuthorityUri;

    @XStreamAlias("resource_set_as")
    @XStreamAsAttribute
    private String resourceSetAsNumbers = "";

    @XStreamAlias("resource_set_ipv4")
    @XStreamAsAttribute
    private String ipv4ResourceSet = "";

    @XStreamAlias("resource_set_ipv6")
    @XStreamAsAttribute
    private String ipv6ResourceSet = "";

    @XStreamAlias("certificate")
    @XStreamImplicit(itemFieldName = "certificate")
    private List<ResourceClass> resourceClasses;

    @XStreamConverter(X509ResourceCertificateBase64Converter.class)
    @XStreamAlias("issuer")
    private X509ResourceCertificate issuer;

    @XStreamAlias("resource_set_notafter")
    @XStreamAsAttribute
    private DateTime validityNotAfter;

    @XStreamAlias("suggested_sia_head")
    @XStreamAsAttribute
    private String siaHeadUri;

    public DateTime getValidityNotAfter() {
        return validityNotAfter;
    }

    ResourceClassPayload setValidityNotAfter(DateTime validityNotAfter) {
        this.validityNotAfter = validityNotAfter;
        return this;
    }

    public String getSiaHeadUri() {
        return siaHeadUri;
    }

    ResourceClassPayload setSiaHeadUri(String siaHeadUri) {
        this.siaHeadUri = siaHeadUri;
        return this;
    }

    public String getClassName() {
        return className;
    }

    protected ResourceClassPayload setClassName(String className) {
        this.className = className;
        return this;
    }

    public String[] getCertificateAuthorityUri() {
        return certificateAuthorityUri == null ? null : certificateAuthorityUri.split(",");
    }

    protected ResourceClassPayload setCertificateAuthorityUri(String... certificateAuthorityUri) {
        this.certificateAuthorityUri = StringUtils.join(certificateAuthorityUri, ",");
        return this;
    }

    public String[] getIpv4ResourceSet() {
        return ipv4ResourceSet == null ? null : ipv4ResourceSet.split(",");
    }

    protected ResourceClassPayload setIpv4ResourceSet(String... ipv4ResourceSet) {
        if (ipv4ResourceSet != null) {
            this.ipv4ResourceSet = StringUtils.join(ipv4ResourceSet, ",");
        }

        return this;
    }

    public String[] getIpv6ResourceSet() {
        return ipv6ResourceSet == null ? null : ipv6ResourceSet.split(",");
    }

    protected ResourceClassPayload setIpv6ResourceSet(String... ipv6ResourceSet) {
        if (ipv6ResourceSet != null) {
            this.ipv6ResourceSet = StringUtils.join(ipv6ResourceSet, ",");
        }

        return this;
    }

    public String[] getResourceSetAsNumbers() {
        return resourceSetAsNumbers != null ? resourceSetAsNumbers.split(",") : null;
    }

    protected ResourceClassPayload setResourceSetAsNumbers(String... resourceSetAsNumbers) {
        if (resourceSetAsNumbers != null) {
            this.resourceSetAsNumbers = StringUtils.join(resourceSetAsNumbers, ",");
        }
        return this;
    }

    public List<ResourceClass> getResourceClasses() {
        return resourceClasses;
    }

    // purely for junit testin
    public void addResourceClass(ResourceClass resourceClass) {
        if (resourceClasses == null) {
            resourceClasses = new ArrayList<ResourceClass>();
        }

        resourceClasses.add(resourceClass);
    }

    protected ResourceClassPayload setResourceClasses(List<ResourceClass> resourceClasses) {
        this.resourceClasses = resourceClasses;
        return this;
    }

    public X509ResourceCertificate getIssuer() {
        return issuer;
    }

    protected ResourceClassPayload setIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
