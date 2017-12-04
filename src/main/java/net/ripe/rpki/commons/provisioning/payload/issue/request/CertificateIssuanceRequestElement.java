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
package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * See <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1</a>
 */
public class CertificateIssuanceRequestElement {

    private String className;
    private IpResourceSet allocatedAsn;
    private IpResourceSet allocatedIpv4;
    private IpResourceSet allocatedIpv6;
    private PKCS10CertificationRequest certificateRequest;

    public String getClassName() {
        return className;
    }

    CertificateIssuanceRequestElement setClassName(String className) {
        this.className = className;
        return this;
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

    CertificateIssuanceRequestElement setAllocatedAsn(IpResourceSet asns) {
        validateResourceSetContainsOnlyType(asns, IpResourceType.ASN);
        this.allocatedAsn = asns;
        return this;
    }

    CertificateIssuanceRequestElement setAllocatedIpv4(IpResourceSet allocatedIpv4) {
        validateResourceSetContainsOnlyType(allocatedIpv4, IpResourceType.IPv4);
        this.allocatedIpv4 = allocatedIpv4;
        return this;
    }

    CertificateIssuanceRequestElement setAllocatedIpv6(IpResourceSet allocatedIpv6) {
        validateResourceSetContainsOnlyType(allocatedIpv6, IpResourceType.IPv6);
        this.allocatedIpv6 = allocatedIpv6;
        return this;
    }

    private void validateResourceSetContainsOnlyType(IpResourceSet resourceSet, IpResourceType type) {
        if (resourceSet == null) {
            return;
        }
        for (IpResource resource : resourceSet) {
            Validate.isTrue(resource.getType().equals(type), "Can only add resources of type: " + type);
        }
    }


    public PKCS10CertificationRequest getCertificateRequest() {
        return certificateRequest;
    }

    CertificateIssuanceRequestElement setCertificateRequest(PKCS10CertificationRequest certificate) {
        this.certificateRequest = certificate;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
