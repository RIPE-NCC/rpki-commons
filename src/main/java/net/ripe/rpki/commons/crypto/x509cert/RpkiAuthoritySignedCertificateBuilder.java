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
package net.ripe.rpki.commons.crypto.x509cert;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.net.URI;

/**
 * Builder for any not self-signed certificates.
 */
public abstract class RpkiAuthoritySignedCertificateBuilder extends GenericRpkiCertificateBuilder {

    private URI crlUri;
    private URI parentResourceCertificatePublicationUri;

    public void withCrlUri(URI crlUri) {
        Validate.notNull(crlUri, "CRL Uri can not be null");
        validateIsRsyncUri(crlUri);
        this.crlUri = crlUri;
    }

    public void withParentResourceCertificatePublicationUri(URI parentResourceCertificatePublicationUri) {
        this.parentResourceCertificatePublicationUri = parentResourceCertificatePublicationUri;
    }

    @Override
    protected X509ResourceCertificateBuilder createGenericRpkiCertificateBuilder(int keyUsage) {
        final X509ResourceCertificateBuilder builder = super.createGenericRpkiCertificateBuilder(keyUsage);

        builder.withCrlDistributionPoints(crlUri);

        builder.withAuthorityInformationAccess(new X509CertificateInformationAccessDescriptor(
            X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, parentResourceCertificatePublicationUri));

        builder.withAuthorityKeyIdentifier(true);
        return builder;
    }

    @Override
    protected void validateFields() {
        super.validateFields();
        Validate.notNull(crlUri, "CRL URI is required (except for self-signed (root) certificates)");
        Validate.notNull(parentResourceCertificatePublicationUri, "Parent Certificate Publication URI is required");
    }
}
