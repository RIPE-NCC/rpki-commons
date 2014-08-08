/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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

import java.net.*;
import java.util.*;

import org.apache.commons.lang.*;
import org.bouncycastle.asn1.x509.*;

/**
 * Builder for X509ResourceCertificates used by RPKI CAs
 */
public class RpkiCaCertificateBuilder extends GenericRpkiCertificateBuilder {

    private URI caRepositoryUri;
    private URI manifestUri;
    private URI rrdpNotifyUri;

    public void withCaRepositoryUri(URI caRepositoryUri) {
        validateIsRsyncUri(caRepositoryUri);
        this.caRepositoryUri = caRepositoryUri;
    }

    public void withManifestUri(URI manifestUri) {
        validateIsRsyncUri(manifestUri);
        this.manifestUri = manifestUri;
    }

    public void withRrdpNotifyUri(URI rrdpNotifyUri) {
        this.rrdpNotifyUri = rrdpNotifyUri;
    }

    public X509ResourceCertificate build() {
        validateFields();

        X509ResourceCertificateBuilder builder = createGenericRpkiCertificateBuilder();

        // Implicitly required by standards
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withAuthorityKeyIdentifier(true);

        List<X509CertificateInformationAccessDescriptor> sias = new ArrayList<X509CertificateInformationAccessDescriptor>();
        sias.add(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri));
        sias.add(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri));
        if (rrdpNotifyUri != null) {
            sias.add(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RRDP_NOTIFY, rrdpNotifyUri));
        }
        builder.withSubjectInformationAccess(sias.toArray(new X509CertificateInformationAccessDescriptor[sias.size()]));

        return builder.build();
    }


    @Override
    protected void validateFields() {
        super.validateFields();

        Validate.notNull(caRepositoryUri, "CA Repository URI is required");
        Validate.notNull(manifestUri, "Manifest URI is required");

    }
}
