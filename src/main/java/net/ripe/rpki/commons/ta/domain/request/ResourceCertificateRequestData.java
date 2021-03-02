/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
package net.ripe.rpki.commons.ta.domain.request;


import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.util.EqualsSupport;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.security.PublicKey;

public class ResourceCertificateRequestData extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final X500Principal subjectDN;
    private final X509CertificateInformationAccessDescriptor[] subjectInformationAccess;
    private final byte[] encodedSubjectPublicKey;


    public ResourceCertificateRequestData(String resourceClassName, X500Principal subjectDN, PublicKey subjectPublicKey,
                                          X509CertificateInformationAccessDescriptor[] subjectInformationAccess, IpResourceSet ipResourceSet) {
        this(resourceClassName, subjectDN, subjectPublicKey.getEncoded(), subjectInformationAccess);
    }

    public ResourceCertificateRequestData(String resourceClassName, X500Principal subjectDN, byte[] encodedSubjectPublicKey,
                                          X509CertificateInformationAccessDescriptor[] subjectInformationAccess) {
        this.resourceClassName = resourceClassName;
        this.subjectDN = subjectDN;
        this.encodedSubjectPublicKey = encodedSubjectPublicKey;
        this.subjectInformationAccess = subjectInformationAccess;
    }

    public String getResourceClassName() {
        return resourceClassName;
    }

    public X500Principal getSubjectDN() {
        return subjectDN;
    }

    public byte[] getEncodedSubjectPublicKey() {
        return encodedSubjectPublicKey;
    }

    public X509CertificateInformationAccessDescriptor[] getSubjectInformationAccess() {
        return subjectInformationAccess;
    }
}
