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
package net.ripe.rpki.commons.crypto.x509cert;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.net.URI;

/**
 * Builder for Embedded EE Certificates used in RpkiSignedObjects
 */
public class RpkiSignedObjectEeCertificateBuilder extends GenericRpkiCertificateBuilder {

    private URI cmsPublicationUri;

    public void withCorrespondingCmsPublicationPoint(URI cmsPublicationUri) {
        this.cmsPublicationUri = cmsPublicationUri;
    }

    public X509ResourceCertificate build() {
        validateFields();

        X509ResourceCertificateBuilder builder = createGenericRpkiCertificateBuilder();

        // Implicit by standard:
        builder.withCa(false);
        builder.withKeyUsage(KeyUsage.digitalSignature);

        X509CertificateInformationAccessDescriptor[] siaDescriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, cmsPublicationUri)
        };
        builder.withSubjectInformationAccess(siaDescriptors);

        return builder.build();
    }

    @Override
    protected void validateFields() {
        super.validateFields();
        Validate.isTrue(!isSelfSigned(), "EE Certificate can not be self-signed (use EE keypair for public and signing the object, sign this cert with parent key pair)");
        Validate.notNull(cmsPublicationUri, "CMS Object Publication URI is required");
    }
}
