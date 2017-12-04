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
package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadParser;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
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
import org.joda.time.DateTimeUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;


public class ProvisioningCmsObjectBuilder {

    private static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.28");

    private X509Certificate cmsCertificate;

    private X509CRL crl;

    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;

    private String payloadContent;

    public ProvisioningCmsObjectBuilder withCmsCertificate(X509Certificate cmsCertificate) {
        this.cmsCertificate = cmsCertificate;
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
        parser.parseCms("n/a", generateCms(privateKey));

        ValidationResult validationResult = parser.getValidationResult();
        if (validationResult.hasFailures()) {
            List<String> failureMessages = new ArrayList<String>();
            List<ValidationCheck> failures = validationResult.getFailures(new ValidationLocation("generated.cms"));
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
        } catch (CMSException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (IOException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (OperatorCreationException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (CRLException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        } catch (CertificateEncodingException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        }
    }

    private byte[] doGenerate(PrivateKey privateKey) throws CMSException, IOException, CertificateEncodingException, CRLException, OperatorCreationException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        addCertificateAndCrl(generator);
        addSignerInfo(generator, privateKey);

        CMSSignedData data = generator.generate(new CMSProcessableByteArray(CONTENT_TYPE, payloadContent.getBytes(Charset.forName("UTF-8"))), true);

        return data.getEncoded();
    }

    private void addSignerInfo(CMSSignedDataGenerator generator, PrivateKey privateKey) throws OperatorCreationException {
        ContentSigner signer = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM).setProvider(signatureProvider).build(privateKey);
        DigestCalculatorProvider digestProvider = BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER;
        SignerInfoGenerator gen = new JcaSignerInfoGeneratorBuilder(digestProvider).setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(createSignedAttributes())).build(signer, X509CertificateUtil.getSubjectKeyIdentifier(cmsCertificate));
        generator.addSignerInfoGenerator(gen);
    }

    private void addCertificateAndCrl(CMSSignedDataGenerator generator) throws CertificateEncodingException, CMSException, CRLException {
        List<X509Extension> certificates = new ArrayList<X509Extension>();
        certificates.add(cmsCertificate);

        generator.addCertificates(new JcaCertStore(certificates));
        generator.addCRLs(new JcaCRLStore(Collections.singleton(crl)));
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>(); // NOPMD
        // -
        // ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(DateTimeUtils.currentTimeMillis()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }

}