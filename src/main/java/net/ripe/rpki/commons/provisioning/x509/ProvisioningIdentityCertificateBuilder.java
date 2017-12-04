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
package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;


public class ProvisioningIdentityCertificateBuilder {

    private static final int DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW = 10;

    private X509CertificateBuilderHelper builderHelper;

    private KeyPair selfSigningKeyPair;
    private X500Principal selfSigningSubject;
    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;


    public ProvisioningIdentityCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
    }

    public ProvisioningIdentityCertificateBuilder withSelfSigningKeyPair(KeyPair selfSigningKeyPair) {
        this.selfSigningKeyPair = selfSigningKeyPair;
        return this;
    }

    public ProvisioningIdentityCertificateBuilder withSelfSigningSubject(X500Principal selfSigningSubject) {
        this.selfSigningSubject = selfSigningSubject;
        return this;
    }

    /**
     * Only call this if you need to use a special signature provider, eg for HSM. Leave to use default otherwise
     *
     * @see X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER
     */
    public ProvisioningIdentityCertificateBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public ProvisioningIdentityCertificate build() {
        Validate.notNull(selfSigningKeyPair, "Self Signing KeyPair is required");
        Validate.notNull(selfSigningSubject, "Self Signing DN is required");
        Validate.notNull(signatureProvider, "Signature Provider is required");
        setUpImplicitRequirementsForBuilderHelper();
        builderHelper.withPublicKey(selfSigningKeyPair.getPublic());
        builderHelper.withSigningKeyPair(selfSigningKeyPair);
        builderHelper.withSubjectDN(selfSigningSubject);
        builderHelper.withIssuerDN(selfSigningSubject);
        builderHelper.withSignatureProvider(signatureProvider);
        return new ProvisioningIdentityCertificate(builderHelper.generateCertificate());
    }

    private void setUpImplicitRequirementsForBuilderHelper() {
        builderHelper.withSerial(BigInteger.ONE); // Self-signed! So this is the first!
        builderHelper.withValidityPeriod(new ValidityPeriod(new DateTime(), new DateTime().plusYears(DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW)));
        builderHelper.withCa(true);
        builderHelper.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }
}
