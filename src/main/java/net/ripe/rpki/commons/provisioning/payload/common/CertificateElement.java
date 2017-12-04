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

import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.builder.ToStringBuilder;

import java.net.URI;
import java.util.Iterator;
import java.util.List;

@XStreamConverter(CertificateElementConverter.class)
public class CertificateElement {

    private List<URI> issuerCertificatePublicationLocationUris;

    private IpResourceSet allocatedAsn;

    private IpResourceSet allocatedIpv4;

    private IpResourceSet allocatedIpv6;

    private X509ResourceCertificate certificate;

    // Setters
    CertificateElement setIssuerCertificatePublicationLocation(List<URI> issuerCertificatePublicationLocation) {   // NOPMD no clone of array stored
        this.issuerCertificatePublicationLocationUris = issuerCertificatePublicationLocation;
        return this;
    }

    CertificateElement setCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public CertificateElement setIpResourceSet(IpResourceSet ipResourceSet) {
        allocatedAsn = new IpResourceSet();
        allocatedIpv4 = new IpResourceSet();
        allocatedIpv6 = new IpResourceSet();

        Iterator<IpResource> iter = ipResourceSet.iterator();
        while (iter.hasNext()) {
            IpResource resource = iter.next();
            if (resource.getType().equals(IpResourceType.ASN)) {
                allocatedAsn.add(resource);
            } else if (resource.getType().equals(IpResourceType.IPv4)) {
                allocatedIpv4.add(resource);
            } else if (resource.getType().equals(IpResourceType.IPv6)) {
                allocatedIpv6.add(resource);
            }
        }

        return this;
    }

    // Getters
    public List<URI> getIssuerCertificatePublicationUris() {
        return issuerCertificatePublicationLocationUris;
    }

    public URI getRsyncAIAPointer() {
        for (URI uri : issuerCertificatePublicationLocationUris) {
            if (uri.toString().startsWith("rsync")) {
                return uri;
            }
        }
        return null;

    }

    public IpResourceSet getAllocatedAsn() {
        return allocatedAsn;
    }

    public IpResourceSet getAllocatedIpv4() {
        return allocatedIpv4;
    }

    public IpResourceSet getAllocatedIpv6() {
        return allocatedIpv6;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }

    public void setAllocatedAsn(IpResourceSet allocatedAsn) {
        this.allocatedAsn = allocatedAsn;
    }

    public void setAllocatedIpv4(IpResourceSet allocatedIpv4) {
        this.allocatedIpv4 = allocatedIpv4;
    }

    public void setAllocatedIpv6(IpResourceSet allocatedIpv6) {
        this.allocatedIpv6 = allocatedIpv6;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
