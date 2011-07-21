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
package net.ripe.commons.provisioning.cms;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509CertificateUtil;
import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.PayloadParser;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.joda.time.DateTimeUtils;


public class ProvisioningCmsObjectBuilder {

    private static final String DIGEST_ALGORITHM_OID = CMSSignedDataGenerator.DIGEST_SHA256;

    private static final String CONTENT_TYPE = "1.2.840.113549.1.9.16.1.28";

    private X509Certificate cmsCertificate;

    private X509Certificate[] caCertificates;

    private X509CRL crl;

    private String signatureProvider;

    private String payloadContent;

    public ProvisioningCmsObjectBuilder withCmsCertificate(X509Certificate cmsCertificate) {
        this.cmsCertificate = cmsCertificate;
        return this;
    }

    public ProvisioningCmsObjectBuilder withCaCertificate(X509Certificate... caCertificates) { // NOPMD
                                                                                               // -
                                                                                               // ArrayIsStoredDirectly
        this.caCertificates = caCertificates;
        return this;
    }

    public ProvisioningCmsObjectBuilder withCrl(X509CRL crl) {
        this.crl = crl;
        return this;
    }

    public ProvisioningCmsObjectBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public ProvisioningCmsObjectBuilder withPayloadContent(AbstractProvisioningPayload payload) {
        this.payloadContent = PayloadParser.serialize(payload);
        return this;
    }

    public ProvisioningCmsObject build(PrivateKey privateKey) {
        Validate.notEmpty(payloadContent, "Payload content is required");

        Validate.notNull(cmsCertificate, "cms certificate is required");
        Validate.notNull(crl, "crl is required");

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("<generated>", generateCms(privateKey));

        ValidationResult validationResult = parser.getValidationResult();
        if (validationResult.hasFailures()) {
            List<String> failureMessages = new ArrayList<String>();
            List<ValidationCheck> failures = validationResult.getFailures("<generated>");
            for (ValidationCheck check : failures) {
                failureMessages.add(check.getKey());
            }
            Validate.isTrue(false, "Validation of generated CMS object failed with following errors: " + StringUtils.join(failureMessages, ","));
        }

        return parser.getProvisioningCmsObject();
    }

    private byte[] generateCms(PrivateKey privateKey) {
        try {
            return doGenerate(privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (NoSuchProviderException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (CMSException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (IOException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (CertStoreException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (CertificateEncodingException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        }
    }

    private byte[] doGenerate(PrivateKey privateKey) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, CertStoreException, CMSException, NoSuchProviderException, IOException, CertificateEncodingException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        addCertificateAndCrl(generator);
        generator.addSigner(privateKey, X509CertificateUtil.getSubjectKeyIdentifier(cmsCertificate), DIGEST_ALGORITHM_OID, createSignedAttributes(), null);

        CMSSignedData data = generator.generate(CONTENT_TYPE, new CMSProcessableByteArray(payloadContent.getBytes(Charset.forName("UTF-8"))), true, signatureProvider);

        return data.getEncoded();
    }

    private void addCertificateAndCrl(CMSSignedDataGenerator generator) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            CertStoreException, CMSException {
        List<X509Extension> signedObjects = new ArrayList<X509Extension>();
        signedObjects.add(cmsCertificate);
        if (caCertificates != null) {
            signedObjects.addAll(Arrays.asList(caCertificates));
        }
        signedObjects.add(crl);

        CollectionCertStoreParameters certStoreParameters = new CollectionCertStoreParameters(signedObjects);
        CertStore certStore = CertStore.getInstance("Collection", certStoreParameters);
        generator.addCertificatesAndCRLs(certStore);
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>(); // NOPMD
                                                                                                                // -
                                                                                                                // ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(DateTimeUtils.currentTimeMillis()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }

}
