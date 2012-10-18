/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.cms;

import net.ripe.commons.certification.Asn1Util;
import net.ripe.commons.certification.x509cert.X509CertificateUtil;
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
import org.joda.time.DateTimeUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;

public abstract class RpkiSignedObjectBuilder {

    protected byte[] generateCms(X509Certificate signingCertificate, PrivateKey privateKey, String signatureProvider, ASN1ObjectIdentifier contentTypeOid, ASN1Encodable encodableContent) {
        byte[] result;
        try {
            result = doGenerate(signingCertificate, privateKey, signatureProvider, contentTypeOid, encodableContent);
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
        }
        return result;
    }

    private byte[] doGenerate(X509Certificate signingCertificate, PrivateKey privateKey, String signatureProvider, ASN1ObjectIdentifier contentTypeOid, ASN1Encodable encodableContent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertStoreException, CMSException, NoSuchProviderException, IOException, CertificateEncodingException {
        byte[] subjectKeyIdentifier = X509CertificateUtil.getSubjectKeyIdentifier(signingCertificate);
        Validate.notNull(subjectKeyIdentifier, "certificate must contain SubjectKeyIdentifier extension");

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        AttributeTable signedAttributeTable = createSignedAttributes();
        generator.addSigner(privateKey, subjectKeyIdentifier, RpkiSignedObject.DIGEST_ALGORITHM_OID, signedAttributeTable, null);
        generator.addCertificates(new JcaCertStore(Collections.singleton(signingCertificate)));

        byte[] content = Asn1Util.encode(encodableContent);
        CMSSignedData data = generator.generate(contentTypeOid.getId(), new CMSProcessableByteArray(content), true, signatureProvider);
        return data.getEncoded();
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>(); //NOPMD - ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(DateTimeUtils.currentTimeMillis()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }
}
