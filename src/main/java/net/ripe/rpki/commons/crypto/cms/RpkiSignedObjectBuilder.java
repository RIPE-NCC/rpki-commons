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
package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

public abstract class RpkiSignedObjectBuilder {

    protected byte[] generateCms(X509Certificate signingCertificate, PrivateKey privateKey, String signatureProvider, ASN1ObjectIdentifier contentTypeOid, byte[] content) {
        byte[] result;
        try {
            result = doGenerate(signingCertificate, privateKey, signatureProvider, contentTypeOid, content);
        } catch (NoSuchAlgorithmException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (NoSuchProviderException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (CMSException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (IOException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (CertStoreException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (CertificateEncodingException e) {
            throw new RpkiSignedObjectBuilderException(e);
        } catch (OperatorCreationException e) {
            throw new RpkiSignedObjectBuilderException(e);
        }
        return result;
    }

    private byte[] doGenerate(X509Certificate signingCertificate, PrivateKey privateKey, String signatureProvider, ASN1ObjectIdentifier contentTypeOid, byte[] content) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertStoreException, CMSException, NoSuchProviderException, IOException, CertificateEncodingException, OperatorCreationException {
        byte[] subjectKeyIdentifier = X509CertificateUtil.getSubjectKeyIdentifier(signingCertificate);
        Validate.notNull(subjectKeyIdentifier, "certificate must contain SubjectKeyIdentifier extension");

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        addSignerInfo(generator, privateKey, signatureProvider, signingCertificate);
        generator.addCertificates(new JcaCertStore(Collections.singleton(signingCertificate)));

        CMSSignedData data = generator.generate(new CMSProcessableByteArray(contentTypeOid, content), true);
        return data.getEncoded();
    }

    private void addSignerInfo(CMSSignedDataGenerator generator, PrivateKey privateKey, String signatureProvider, X509Certificate signingCertificate) throws OperatorCreationException {
        ContentSigner signer = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM).setProvider(signatureProvider).build(privateKey);
        DigestCalculatorProvider digestProvider = BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER;
        SignerInfoGenerator gen = new JcaSignerInfoGeneratorBuilder(digestProvider).setSignedAttributeGenerator(
            new DefaultSignedAttributeTableGenerator(createSignedAttributes(signingCertificate.getNotBefore())) {
                @Override
                public AttributeTable getAttributes(Map parameters) {
                    return super.getAttributes(parameters).remove(CMSAttributes.cmsAlgorithmProtect);
                }
            }
        ).build(signer, X509CertificateUtil.getSubjectKeyIdentifier(signingCertificate));
        generator.addSignerInfoGenerator(gen);
    }

    private AttributeTable createSignedAttributes(Date signingTime) {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>(); //NOPMD - ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime)));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }
}
