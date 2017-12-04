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

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;
import org.apache.commons.lang.Validate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Builder for 'Certificate Issuance Request'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1</a>
 */
public class CertificateIssuanceRequestPayloadBuilder extends AbstractPayloadBuilder<CertificateIssuanceRequestPayload> {

    private String className;
    private IpResourceSet asn;
    private IpResourceSet ipv4ResourceSet;
    private IpResourceSet ipv6ResourceSet;
    private PKCS10CertificationRequest certificateRequest;

    public CertificateIssuanceRequestPayloadBuilder withClassName(String className) {
        this.className = className;
        return this;
    }

    /**
     * Provide empty list to request *NO* Asns. Leave null to request *ALL* eligible.
     */
    public CertificateIssuanceRequestPayloadBuilder withAllocatedAsn(IpResourceSet asnResourceSet) {
        this.asn = asnResourceSet;
        return this;
    }

    /**
     * Provide empty list to request *NO* IPv4. Leave null to request *ALL* eligible.
     */
    public CertificateIssuanceRequestPayloadBuilder withIpv4ResourceSet(IpResourceSet ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    /**
     * Provide empty list to request *NO* IPv6. Leave null to request *ALL* eligible.
     */
    public CertificateIssuanceRequestPayloadBuilder withIpv6ResourceSet(IpResourceSet ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }


    public CertificateIssuanceRequestPayloadBuilder withCertificateRequest(PKCS10CertificationRequest certificateRequest) {
        this.certificateRequest = certificateRequest;
        return this;
    }

    @Override
    public CertificateIssuanceRequestPayload build() {
        Validate.notNull(className, "No className provided");
        Validate.notNull(certificateRequest);
        CertificateIssuanceRequestElement content = new CertificateIssuanceRequestElement()
                .setClassName(className)
                .setAllocatedAsn(asn)
                .setAllocatedIpv4(ipv4ResourceSet)
                .setAllocatedIpv6(ipv6ResourceSet)
                .setCertificateRequest(certificateRequest);

        return new CertificateIssuanceRequestPayload(content);
    }
}
