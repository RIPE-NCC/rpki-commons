package net.ripe.commons.provisioning.message.common;

import java.util.List;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.joda.time.DateTime;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import com.thoughtworks.xstream.annotations.XStreamImplicit;

public class GenericClassElement {

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
    protected List<CertificateElement> certificateElements;

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

    public void setValidityNotAfter(DateTime validityNotAfter) {
        this.validityNotAfter = validityNotAfter;
    }

    public String getSiaHeadUri() {
        return siaHeadUri;
    }

    public void setSiaHeadUri(String siaHeadUri) {
        this.siaHeadUri = siaHeadUri;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String[] getCertificateAuthorityUri() {
        return certificateAuthorityUri == null ? null : certificateAuthorityUri.split(",");
    }

    public void setCertificateAuthorityUri(String... certificateAuthorityUri) {
        this.certificateAuthorityUri = StringUtils.join(certificateAuthorityUri, ",");
    }

    public String[] getIpv4ResourceSet() {
        return ipv4ResourceSet == null ? null : ipv4ResourceSet.split(",");
    }

    public void setIpv4ResourceSet(String... ipv4ResourceSet) {
        if (ipv4ResourceSet != null) {
            this.ipv4ResourceSet = StringUtils.join(ipv4ResourceSet, ",");
        }
    }

    public String[] getIpv6ResourceSet() {
        return ipv6ResourceSet == null ? null : ipv6ResourceSet.split(",");
    }

    public void setIpv6ResourceSet(String... ipv6ResourceSet) {
        if (ipv6ResourceSet != null) {
            this.ipv6ResourceSet = StringUtils.join(ipv6ResourceSet, ",");
        }
    }

    public String[] getResourceSetAsNumbers() {
        return resourceSetAsNumbers != null ? resourceSetAsNumbers.split(",") : null;
    }

    public void setResourceSetAsNumbers(String... resourceSetAsNumbers) {
        if (resourceSetAsNumbers != null) {
            this.resourceSetAsNumbers = StringUtils.join(resourceSetAsNumbers, ",");
        }
    }

    public X509ResourceCertificate getIssuer() {
        return issuer;
    }

    public void setIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
