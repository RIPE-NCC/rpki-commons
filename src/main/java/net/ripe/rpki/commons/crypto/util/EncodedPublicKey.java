/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.crypto.util;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.security.PublicKey;

/**
 * While software keys can be persisted nCipher keys cannot.
 * For KeyPairEntity we put them into a keystore but that did not
 * fit into the architecture for ResourceCertificateRequestData.
 * ResourceCertificateRequestData contains the encoded representation of
 * the subject public key and when it fed into the ResourceCertificateBuilder
 * (which send it further to X509CertificateBuilder) it is wrapped into
 * this class.
 */
public class EncodedPublicKey implements PublicKey {

    private static final long serialVersionUID = 2L;

    private final ASN1Sequence sequence;


    public EncodedPublicKey(byte[] encoded) {
        this.sequence = ASN1Sequence.getInstance(encoded);
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        if (!algId.getAlgorithm().on(PKCSObjectIdentifiers.pkcs_1)) {
            throw new IllegalArgumentException("Not a PKCS#1 signature algorithm" + algId.getAlgorithm());
        }
    }

    @Override
    public byte[] getEncoded() {
        try {
            return sequence.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Lost access to loaded public key data", e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }
}
