package net.ripe.commons.provisioning.payload.common;

import java.net.URI;
import java.util.Iterator;
import java.util.List;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;

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

    public void setCertUris(List<URI> certUris) {
        this.certificateAuthorityUri = StringUtils.join(certUris, ",");
    }

    public IpResourceSet getResourceSetAsNumbers() {
        return resourceSetAsNumbers == null ? null : IpResourceSet.parse(resourceSetAsNumbers);
    }

    public IpResourceSet getIpv4ResourceSet() {
        return ipv4ResourceSet == null ? null : IpResourceSet.parse(ipv4ResourceSet);
    }

    public IpResourceSet getIpv6ResourceSet() {
        return ipv6ResourceSet == null ? null : IpResourceSet.parse(ipv6ResourceSet);
    }

    public void setIpResourceSet(IpResourceSet ipResourceSet) {
        IpResourceSet asns = new IpResourceSet();
        IpResourceSet ipv4 = new IpResourceSet();
        IpResourceSet ipv6 = new IpResourceSet();

        Iterator<IpResource> iterator = ipResourceSet.iterator();
        while (iterator.hasNext()) {
            IpResource resource = iterator.next();
            IpResourceType type = resource.getType();
            if (type.equals(IpResourceType.ASN)) {
                asns.add(resource);
            } else if (type.equals(IpResourceType.IPv4)) {
                ipv4.add(resource);
            } else if (type.equals(IpResourceType.IPv6)) {
                ipv6.add(resource);
            }
        }

        if (!asns.isEmpty()) {
            String asnString = asns.toString();
            asnString = StringUtils.replaceChars(asnString, "AS", "");
            asnString = StringUtils.replaceChars(asnString, " ", "");
            resourceSetAsNumbers = asnString;
        }
        if (!ipv4.isEmpty()) {
            String ipv4String = ipv4.toString();
            ipv4ResourceSet = StringUtils.replaceChars(ipv4String, " ", "");
        }
        if (!ipv6.isEmpty()) {
            String ipv6String = ipv6.toString();
            ipv6ResourceSet = StringUtils.replaceChars(ipv6String, " ", "");
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
