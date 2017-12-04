/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.provisioning.payload.common;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import com.thoughtworks.xstream.annotations.XStreamImplicit;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.provisioning.serialization.CertificateUrlListConverter;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.joda.time.DateTime;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;


public class GenericClassElement {

    @XStreamAsAttribute
    @XStreamAlias("class_name")
    private String className;

    @XStreamAlias("cert_url")
    @XStreamAsAttribute
    @XStreamConverter(CertificateUrlListConverter.class)
    private List<URI> certificateAuthorityUri;

    @XStreamAlias("resource_set_as")
    @XStreamAsAttribute
    @XStreamConverter(IpResourceSetProvisioningConverter.class)
    private IpResourceSet resourceSetAs = new IpResourceSet();

    @XStreamAlias("resource_set_ipv4")
    @XStreamAsAttribute
    @XStreamConverter(IpResourceSetProvisioningConverter.class)
    private IpResourceSet resourceSetIpv4 = new IpResourceSet();

    @XStreamAlias("resource_set_ipv6")
    @XStreamAsAttribute
    @XStreamConverter(IpResourceSetProvisioningConverter.class)
    private IpResourceSet resourceSetIpv6 = new IpResourceSet();

    @XStreamAlias("certificate")
    @XStreamImplicit(itemFieldName = "certificate")
    private List<CertificateElement> certificateElements = new ArrayList<CertificateElement>();

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

    public List<URI> getCertificateAuthorityUri() {
        return certificateAuthorityUri;
    }

    public void setCertUris(List<URI> certUris) {
        this.certificateAuthorityUri = certUris;
    }

    public IpResourceSet getResourceSetAsn() {
        return resourceSetAs;
    }

    public IpResourceSet getResourceSetIpv4() {
        return resourceSetIpv4;
    }

    public IpResourceSet getResourceSetIpv6() {
        return resourceSetIpv6;
    }

    public void setIpResourceSet(IpResourceSet ipResourceSet) {
        IpResourceSet asns = new IpResourceSet();
        IpResourceSet ipv4 = new IpResourceSet();
        IpResourceSet ipv6 = new IpResourceSet();

        for (IpResource resource : ipResourceSet) {
            switch (resource.getType()) {
                case ASN:
                    asns.add(resource);
                    break;
                case IPv4:
                    ipv4.add(resource);
                    break;
                case IPv6:
                    ipv6.add(resource);
                    break;
            }
        }

        resourceSetAs = asns;
        resourceSetIpv4 = ipv4;
        resourceSetIpv6 = ipv6;
    }


    public X509ResourceCertificate getIssuer() {
        return issuer;
    }

    public void setIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
    }

    protected List<CertificateElement> getCertificateElements() {
        return certificateElements;
    }

    protected void setCertificateElements(List<CertificateElement> certificateElements) {
        this.certificateElements = certificateElements;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}

