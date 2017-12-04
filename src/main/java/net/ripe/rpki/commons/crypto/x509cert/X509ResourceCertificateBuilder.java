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
import org.bouncycastle.asn1.x509.PolicyInformation;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.EnumSet;

/**
 * Generic Builder for X509ResourceCertificates<br />
 * Note that you may want to use one of the following more specific builders to build standard conform signed object EE or CA certificates:
 *
 * @see RpkiSignedObjectEeCertificateBuilder
 * @see RpkiCaCertificateBuilder
 */
public class X509ResourceCertificateBuilder {

    private X509CertificateBuilderHelper builderHelper;
    private IpResourceSet resources = new IpResourceSet();
    private EnumSet<IpResourceType> inheritedResourceTypes = EnumSet.noneOf(IpResourceType.class);

    public X509ResourceCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
        builderHelper.withResources(resources);
        builderHelper.withPolicies(X509ResourceCertificate.POLICY_INFORMATION);
    }

    public X509ResourceCertificateBuilder withSignatureProvider(String signatureProvider) {
        builderHelper.withSignatureProvider(signatureProvider);
        return this;
    }

    public X509ResourceCertificateBuilder withSerial(BigInteger serial) {
        builderHelper.withSerial(serial);
        return this;
    }

    public X509ResourceCertificateBuilder withSubjectDN(X500Principal subjectDN) {
        builderHelper.withSubjectDN(subjectDN);
        return this;
    }

    public X509ResourceCertificateBuilder withIssuerDN(X500Principal issuerDN) {
        builderHelper.withIssuerDN(issuerDN);
        return this;
    }

    public X509ResourceCertificateBuilder withValidityPeriod(ValidityPeriod validityPeriod) {
        builderHelper.withValidityPeriod(validityPeriod);
        return this;
    }

    public X509ResourceCertificateBuilder withPublicKey(PublicKey publicKey) {
        builderHelper.withPublicKey(publicKey);
        return this;
    }

    public X509ResourceCertificateBuilder withSigningKeyPair(KeyPair signingKey) {
        builderHelper.withSigningKeyPair(signingKey);
        return this;
    }

    public X509ResourceCertificateBuilder withKeyUsage(int keyUsage) {
        builderHelper.withKeyUsage(keyUsage);
        return this;
    }

    public X509ResourceCertificateBuilder withResources(IpResourceSet resources) {
        this.resources = resources;
        builderHelper.withResources(resources);
        return this;
    }

    public X509ResourceCertificateBuilder withCa(boolean ca) {
        builderHelper.withCa(ca);
        return this;
    }

    public X509ResourceCertificateBuilder withSubjectKeyIdentifier(boolean add) {
        builderHelper.withSubjectKeyIdentifier(add);
        return this;
    }

    public X509ResourceCertificateBuilder withAuthorityKeyIdentifier(boolean add) {
        builderHelper.withAuthorityKeyIdentifier(add);
        return this;
    }

    public X509ResourceCertificateBuilder withCrlDistributionPoints(URI... uris) {
        builderHelper.withCrlDistributionPoints(uris);
        return this;
    }

    public X509ResourceCertificateBuilder withAuthorityInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        builderHelper.withAuthorityInformationAccess(descriptors);
        return this;
    }

    public X509ResourceCertificateBuilder withSubjectInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        builderHelper.withSubjectInformationAccess(descriptors);
        return this;
    }

    public X509ResourceCertificateBuilder withPolicies(PolicyInformation... policies) {
        builderHelper.withPolicies(policies);
        return this;
    }

    public X509ResourceCertificate build() {
        if (inheritedResourceTypes.isEmpty()) {
            Validate.notNull(resources, "no resources");
            Validate.isTrue(!resources.isEmpty(), "empty resources");
        }
        return new X509ResourceCertificate(builderHelper.generateCertificate());
    }

    public X509ResourceCertificateBuilder withInheritedResourceTypes(EnumSet<IpResourceType> resourceTypes) {
        this.inheritedResourceTypes = resourceTypes;
        builderHelper.withInheritedResourceTypes(resourceTypes);
        return this;
    }
}
