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

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.provisioning.payload.issue.response.CertificateIssuanceResponseClassElement;
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponseClassElement;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class GenericClassElementBuilder {

    private String className;
    private List<URI> certificateAuthorityUri = new ArrayList<URI>();
    private IpResourceSet ipResourceSet;
    private DateTime validityNotAfter;
    private String siaHeadUri;
    private List<CertificateElement> certificateElements = new ArrayList<CertificateElement>();
    private X509ResourceCertificate issuer;

    public GenericClassElementBuilder withValidityNotAfter(DateTime notAfter) {
        this.validityNotAfter = notAfter;
        return this;
    }

    public GenericClassElementBuilder withSiaHeadUri(String siaHead) {
        this.siaHeadUri = siaHead;
        return this;
    }

    public GenericClassElementBuilder withClassName(String className) {
        this.className = className;
        return this;
    }

    public GenericClassElementBuilder withIpResourceSet(IpResourceSet ipResourceSet) {
        this.ipResourceSet = ipResourceSet;
        return this;
    }


    public GenericClassElementBuilder withCertificateAuthorityUri(List<URI> caUri) {
        this.certificateAuthorityUri = caUri;
        return this;
    }

    public GenericClassElementBuilder withCertificateElements(List<CertificateElement> certificateElements) {
        this.certificateElements = certificateElements;
        return this;
    }

    public GenericClassElementBuilder withIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
        return this;
    }

    private void validateFields() {
        Validate.notNull(className, "No className provided");
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificateAuthorityUri);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(issuer, "issuer certificate is required");

        Validate.notNull(validityNotAfter, "Validity not after is required");
        Validate.isTrue(validityNotAfter.getZone().equals(DateTimeZone.UTC), "Validity time must be in UTC timezone");
    }

    public ResourceClassListResponseClassElement buildResourceClassListResponseClassElement() {
        validateFields();
        ResourceClassListResponseClassElement classElement = new ResourceClassListResponseClassElement();
        setGenericClassElementFields(classElement);
        classElement.setCertificateElements(certificateElements);
        return classElement;
    }

    public CertificateIssuanceResponseClassElement buildCertificateIssuanceResponseClassElement() {
        validateFields();
        Validate.isTrue(certificateElements.size() == 1);
        CertificateIssuanceResponseClassElement classElement = new CertificateIssuanceResponseClassElement();
        setGenericClassElementFields(classElement);
        classElement.setCertificateElement(certificateElements.get(0));
        return classElement;
    }

    private void setGenericClassElementFields(GenericClassElement classElement) {
        classElement.setClassName(className);
        classElement.setCertUris(certificateAuthorityUri);
        classElement.setIpResourceSet(ipResourceSet);
        classElement.setIssuer(issuer);
        classElement.setValidityNotAfter(validityNotAfter);
        classElement.setSiaHeadUri(siaHeadUri);
    }

}
