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
package net.ripe.rpki.commons.provisioning.x509.pkcs10;

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;


/**
 * Builder for PKCS10CertificationRequests for RPKI CA certificates.
 */
public class RpkiCaCertificateRequestBuilder {

    private X500Principal subject;

    private URI caRepositoryUri;

    private URI manifestUri;

    private URI notificationUri;

    private String signatureAlgorithm = "SHA256withRSA";

    private String signatureProvider = "SunRsaSign";

    public RpkiCaCertificateRequestBuilder withSubject(X500Principal subject) {
        this.subject = subject;
        return this;
    }

    public RpkiCaCertificateRequestBuilder withCaRepositoryUri(URI caRepositoryUri) {
        this.caRepositoryUri = caRepositoryUri;
        return this;
    }

    public RpkiCaCertificateRequestBuilder withManifestUri(URI manifestUri) {
        this.manifestUri = manifestUri;
        return this;
    }

    public RpkiCaCertificateRequestBuilder withNotificationUri(URI notificationUri) {
        this.notificationUri = notificationUri;
        return this;
    }

    /**
     * Default: SunRsaSign
     *
     * @return
     */
    public RpkiCaCertificateRequestBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    /**
     * Default: SHA256withRSA
     *
     * @return
     */
    public RpkiCaCertificateRequestBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public PKCS10CertificationRequest build(KeyPair keyPair) {
        try {
            Extensions extensions = createExtensions();

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(signatureProvider).build(keyPair.getPrivate());

            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
            return builder.build(signer);
        } catch (Exception e) {
            throw new RpkiCaCertificateRequestBuilderException(e);
        }
    }

    private Extensions createExtensions() throws IOException {
        // Make extension for SIA in request. See here:
        // http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
        List<Extension> extensions = new ArrayList<Extension>();

        X509CertificateInformationAccessDescriptor[] descriptors;
        if (notificationUri == null) {
            descriptors = new X509CertificateInformationAccessDescriptor[]{
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri)};
        } else {
            descriptors = new X509CertificateInformationAccessDescriptor[]{
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, notificationUri)};
        }
        AccessDescription[] subjectInformationAccess = X509CertificateInformationAccessDescriptor.convertAccessDescriptors(descriptors);
        DERSequence derSequence = new DERSequence(subjectInformationAccess);

        extensions.add(new Extension(Extension.subjectInfoAccess, false, new DEROctetString(derSequence.getEncoded())));
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        extensions.add(new Extension(Extension.keyUsage, true, new DEROctetString(keyUsage)));

        extensions.add(new Extension(Extension.basicConstraints, true, new DEROctetString(new BasicConstraints(true))));

        return new Extensions(extensions.toArray(new Extension[extensions.size()]));
    }
}
