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

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.apache.commons.lang.Validate;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.EnumSet;

public abstract class GenericRpkiCertificateBuilder {

    private PublicKey publicKey;
    private KeyPair signingKeyPair;
    private BigInteger serial;
    private IpResourceSet resources = new IpResourceSet();
    private EnumSet<IpResourceType> inheritedResourceTypes = EnumSet.noneOf(IpResourceType.class);
    private X500Principal subject;
    private X500Principal issuer;
    private ValidityPeriod validityPeriod;

    private URI crlUri;
    private URI parentResourceCertificatePublicationUri;

    private String signatureProvider = "SunRsaSign";

    public void withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void withSigningKeyPair(KeyPair signingKeyPair) {
        this.signingKeyPair = signingKeyPair;
    }

    public void withSerial(BigInteger serial) {
        this.serial = serial;
    }

    public void withResources(IpResourceSet resources) {
        this.resources = resources;
    }

    public void withInheritedResourceTypes(EnumSet<IpResourceType> resourceTypes) {
        this.inheritedResourceTypes = EnumSet.copyOf(resourceTypes);
    }

    public void withSubjectDN(X500Principal subject) {
        this.subject = subject;
    }

    public void withIssuerDN(X500Principal issuer) {
        this.issuer = issuer;
    }

    public void withValidityPeriod(ValidityPeriod validityPeriod) {
        this.validityPeriod = validityPeriod;
    }


    public void withCrlUri(URI crlUri) {
        Validate.notNull(crlUri, "CRL Uri can not be null");
        validateIsRsyncUri(crlUri);
        this.crlUri = crlUri;
    }

    protected void validateIsRsyncUri(URI crlUri) {
        Validate.isTrue(crlUri.toString().startsWith("rsync:"), "Rsync URI is required, multiple repositories not supported by this builder at this time");
    }

    protected boolean isSelfSigned() {
        return signingKeyPair.getPublic().equals(publicKey);
    }

    public void withParentResourceCertificatePublicationUri(URI parentResourceCertificatePublicationUri) {
        this.parentResourceCertificatePublicationUri = parentResourceCertificatePublicationUri;
    }

    /**
     * Default: SunRsaSign
     */
    public void withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
    }

    protected X509ResourceCertificateBuilder createGenericRpkiCertificateBuilder() {

        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withPublicKey(publicKey);
        builder.withSigningKeyPair(signingKeyPair);

        builder.withSerial(serial);

        builder.withResources(resources);
        builder.withInheritedResourceTypes(inheritedResourceTypes);

        builder.withSubjectDN(subject);
        builder.withIssuerDN(issuer);

        builder.withValidityPeriod(validityPeriod);

        if (!isSelfSigned()) {
            builder.withCrlDistributionPoints(crlUri);

            X509CertificateInformationAccessDescriptor[] aiaDescriptors = {
                    new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, parentResourceCertificatePublicationUri)
            };
            builder.withAuthorityInformationAccess(aiaDescriptors);
            builder.withAuthorityKeyIdentifier(true);
        }

        builder.withSignatureProvider(signatureProvider);

        builder.withSubjectKeyIdentifier(true);

        return builder;
    }

    protected void validateFields() {
        Validate.notNull(publicKey, "Public Key is required");
        Validate.notNull(signingKeyPair, "Signing Key Pair is required");
        Validate.notNull(serial, "Serial is required");
        Validate.isTrue(!inheritedResourceTypes.isEmpty() || !resources.isEmpty(), "Resources are required. Inherited resources are allowed but not advised (unless you are building an EE cert for manifests)");
        Validate.notNull(subject, "Subject is required");
        Validate.notNull(issuer, "Issuer is required");
        Validate.notNull(validityPeriod, "ValidityPeriod is required");


        if (!isSelfSigned()) {
            Validate.notNull(crlUri, "CRL URI is required (except for self-signed (root) certificates)");
            Validate.notNull(parentResourceCertificatePublicationUri, "Parent Certificate Publication URI is required");
        }

        Validate.notNull(signatureProvider, "SignatureProvider is required");
    }


}
