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
package net.ripe.rpki.commons.validation.objectvalidators;

import com.google.common.collect.Lists;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateObject;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificate;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

import java.net.URI;
import java.util.List;

/**
 * Represents the context used to validate an issued object. The context
 * contains the issuing certificate, its location, and the effective resource
 * set. The effective resource set must be used, in case the certificate
 * contains inherited IP resources.
 */
public class CertificateRepositoryObjectValidationContext {

    private final List<String> subjectChain;

    private final URI location;

    private final X509CertificateObject certificate;

    private final IpResourceSet resources;

    private IpResourceSet overclaiming = new IpResourceSet();

    public CertificateRepositoryObjectValidationContext(URI location, X509ResourceCertificate certificate) {
        this(location, certificate, certificate.getResources(), Lists.newArrayList(certificate.getSubject().getName()));
    }

    public CertificateRepositoryObjectValidationContext(URI location, X509ResourceCertificate certificate, IpResourceSet resources, List<String> subjectChain) {
        this.location = location;
        this.certificate = certificate;
        this.resources = resources;
        this.subjectChain = subjectChain;
    }

    public URI getLocation() {
        return location;
    }

    public X509ResourceCertificate getCertificate() {
        if (certificate instanceof X509ResourceCertificate) {
            return (X509ResourceCertificate) certificate;
        }
        throw new IllegalStateException("The certificate in the context is not of the type " + X509ResourceCertificate.class);
    }

    public X509RouterCertificate getRouterCertificate() {
        if (certificate instanceof X509RouterCertificate) {
            return (X509RouterCertificate) certificate;
        }
        throw new IllegalStateException("The certificate in the context is not of the type " + X509RouterCertificate.class);
    }

    public X509CertificateObject getUntypedCertificate() {
        return certificate;
    }

    public List<String> getSubjectChain() {
        return subjectChain;
    }

    public URI getManifestURI() {
        return getCertificate().getManifestUri();
    }

    public URI getRepositoryURI() {
        return getCertificate().getRepositoryUri();
    }

    public URI getRpkiNotifyURI() {
        return getCertificate().getRrdpNotifyUri();
    }

    public byte[] getSubjectKeyIdentifier() {
        return getCertificate().getSubjectKeyIdentifier();
    }

    public void addOverclaiming(IpResourceSet overclaiming) {
        this.overclaiming.addAll(overclaiming);
    }

    public CertificateRepositoryObjectValidationContext createChildContext(URI childLocation, X509ResourceCertificate childCertificate) {
        IpResourceSet effectiveResources = getEffectiveResources(childCertificate.deriveResources(resources));
        List<String> childSubjects = Lists.newArrayList(subjectChain);
        childSubjects.add(childCertificate.getSubject().getName());
        return new CertificateRepositoryObjectValidationContext(childLocation, childCertificate, effectiveResources, childSubjects);
    }

    public IpResourceSet getResources() {
        return getEffectiveResources(resources);
    }

    private IpResourceSet getEffectiveResources(IpResourceSet r) {
        IpResourceSet effectiveResources = new IpResourceSet(r);
        effectiveResources.removeAll(overclaiming);
        return effectiveResources;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(location).append(certificate).append(resources).append(overclaiming).toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final CertificateRepositoryObjectValidationContext that = (CertificateRepositoryObjectValidationContext) obj;
        return new EqualsBuilder()
                .append(this.getLocation(), that.getLocation())
                .append(this.getCertificate(), that.getCertificate())
                .append(this.resources, that.resources)
                .append(this.overclaiming, that.overclaiming)
                .isEquals();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }
}
