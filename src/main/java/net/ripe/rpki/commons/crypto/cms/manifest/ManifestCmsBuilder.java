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
package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectBuilder;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.joda.time.DateTime;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Map;
import java.util.TreeMap;

public class ManifestCmsBuilder extends RpkiSignedObjectBuilder {

    private X509ResourceCertificate certificate;
    private BigInteger number;
    private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
    private Map<String, byte[]> files = new TreeMap<String, byte[]>();


    public ManifestCmsBuilder() {
    }

    public boolean containsFile(String fileName) {
        return files.containsKey(fileName);
    }

    public ManifestCmsBuilder withCertificate(X509ResourceCertificate signingCertificate) {
        this.certificate = signingCertificate;
        return this;
    }

    public ManifestCmsBuilder withManifestNumber(BigInteger number) {
        this.number = number;
        return this;
    }

    public ManifestCmsBuilder withThisUpdateTime(DateTime instant) {
        this.thisUpdateTime = instant;
        return this;
    }

    public ManifestCmsBuilder withNextUpdateTime(DateTime instant) {
        this.nextUpdateTime = instant;
        return this;
    }

    public ManifestCmsBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public ManifestCms build(PrivateKey privateKey) {
        String location = "unknown.mft";
        ManifestCmsParser parser = new ManifestCmsParser();
        parser.parse(ValidationResult.withLocation(location), generateCms(certificate.getCertificate(), privateKey, signatureProvider, new ASN1ObjectIdentifier(ManifestCms.CONTENT_TYPE_OID), encodeManifest()));
        return parser.getManifestCms();
    }

    public void addFile(String fileName, byte[] contents) {
        byte[] digestValue = ManifestCms.hashContents(contents);
        files.put(fileName, digestValue);
    }

    ASN1Encodable encodeFileAndHash(String fileName, byte[] hash) {
        ASN1Encodable[] seq = {new DERIA5String(fileName, true), new DERBitString(hash)};
        return new DERSequence(seq);
    }

    ASN1Encodable encodeFileList() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        for (Map.Entry<String, byte[]> fileAndHash : files.entrySet()) {
            seq.add(encodeFileAndHash(fileAndHash.getKey(), fileAndHash.getValue()));
        }
        return new DERSequence(seq);
    }

    /**
     * Note: in DER encoding a field with a value equal to its default should
     * NOT be encoded. So the version field should not be present.
     */
    byte[] encodeManifest() {
        ASN1Encodable[] seq = {
                new ASN1Integer(number),
                new ASN1GeneralizedTime(thisUpdateTime.toDate()),
                new ASN1GeneralizedTime(nextUpdateTime.toDate()),
                new ASN1ObjectIdentifier(ManifestCms.FILE_HASH_ALGORITHM),
                encodeFileList()
        };
        return Asn1Util.encode(new DERSequence(seq));
    }
}
