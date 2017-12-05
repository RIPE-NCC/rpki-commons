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
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.util.Collection;

import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.SHA256WITHRSA_ENCRYPTION_OID;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static net.ripe.rpki.commons.provisioning.ProvisioningObjectMother.CRL;
import static org.bouncycastle.cms.CMSSignedGenerator.DIGEST_SHA256;
import static org.junit.Assert.*;

public class ProvisioningCmsObjectBuilderTest {

    private ProvisioningCmsObject cmsObject;
    private long signingTime;
    private ProvisioningCmsObjectBuilder subject;
    private CMSSignedDataParser signedDataParser;

    @Before
    public void setUp() throws Exception {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        ResourceClassListQueryPayload payload = payloadBuilder.build();

        subject = new ProvisioningCmsObjectBuilder();

        subject.withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate());
        subject.withCrl(CRL);
        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        subject.withPayloadContent(payload);

        signingTime = new DateTime().getMillis() / 1000 * 1000; // truncate milliseconds
        DateTimeUtils.setCurrentMillisFixed(signingTime);
        cmsObject = subject.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
        DateTimeUtils.setCurrentMillisSystem();

        signedDataParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), cmsObject.getEncoded());
        signedDataParser.getSignedContent().drain();
    }

    public static ProvisioningCmsObject createProvisioningCmsObjectForPayload(AbstractProvisioningPayload payload) {
        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder();
        builder.withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate());
        builder.withCrl(CRL);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        builder.withPayloadContent(payload);
        return builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
    }


    @Test(expected = IllegalArgumentException.class)
    public void shouldForceCertificate() throws CMSException {
        subject.withCmsCertificate(null);
        subject.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldForceCrl() throws CMSException {
        subject.withCrl(null);
        subject.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
    }

    @Test
    public void shouldNotForceIdentityCertificate() throws CMSException {
        subject.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectVersionNumber() throws Exception {
        assertEquals(3, signedDataParser.getVersion());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.2
     */
    @Test
    public void shouldCmsObjectHaveCorrectDigestAlgorithm() throws Exception {
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(cmsObject.getEncoded()));
        ContentInfo info = ContentInfo.getInstance(in.readObject());
        SignedData signedData = SignedData.getInstance(info.getContent());
        ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
        ASN1Encodable asn1Object = digestAlgorithms.getObjectAt(0);
        AlgorithmIdentifier algorithmId = AlgorithmIdentifier.getInstance(asn1Object.toASN1Primitive());

        assertEquals(DIGEST_SHA256, algorithmId.getAlgorithm().getId());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectContentType() throws Exception {
        assertEquals(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.28"), signedDataParser.getSignedContent().getContentType());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.4
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedSigningCertificate() throws Exception {
        Collection<? extends X509CertificateHolder> certificates = getCertificates();

        assertNotNull(certificates);
        assertEquals("size", 1, certificates.size());

        X509CertificateHolder holder = certificates.iterator().next();
        assertEquals(new JcaX509CertificateHolder(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate()), holder);
    }

    @SuppressWarnings("unchecked")
    private Collection<? extends X509CertificateHolder> getCertificates() throws NoSuchAlgorithmException, NoSuchProviderException, CMSException,
            CertStoreException {
        return signedDataParser.getCertificates().getMatches(new BouncyCastleUtil.X509CertificateHolderStoreSelector());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.5
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedCrl() throws Exception {
        @SuppressWarnings("unchecked")
        Collection<X509CRL> crls = signedDataParser.getCRLs().getMatches(new BouncyCastleUtil.X509CRLHolderStoreSelector());

        assertNotNull(crls);
        assertFalse(crls.isEmpty());
        assertEquals(new JcaX509CRLHolder(CRL), crls.iterator().next());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6
     */
    @Test
    public void shouldCmsObjectHaveOnlyOneSigner() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();

        assertNotNull(signers);
        assertEquals(1, signers.size());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.1
     */
    @Test
    public void shouldCmsObjectSignerVersionBeCorrect() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();
        assertEquals(3, signer.getVersion());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    @Test
    public void shouldCmsObjectHaveCorrectSubjectKeyIdentifier() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertArrayEquals(X509CertificateUtil.getSubjectKeyIdentifier(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate()), signer.getSID().getSubjectKeyIdentifier());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    @Test
    public void shouldCmsObjectHaveSubjectKeyIdentifierOnly() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertNull(signer.getSID().getIssuer());
        assertNull(signer.getSID().getSerialNumber());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.3
     */
    @Test
    public void shouldCmsObjectHaveCorrectDigestAlgorithmOID() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertEquals(DIGEST_SHA256, signer.getDigestAlgOID());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4
     */
    @Test
    public void shouldCmsObjectHaveSignedAttributes() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertNotNull(signer.getSignedAttributes());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectContentTypeSignedAttribute() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute contentType = attributeTable.get(CMSAttributes.contentType);

        assertNotNull(contentType);
        assertEquals(1, contentType.getAttrValues().size());
        assertEquals(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.28"), contentType.getAttrValues().getObjectAt(0));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.2
     */
    @Test
    public void shouldCmsObjectHaveCorrectMessageDigestSignedAttribute() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute messageDigest = attributeTable.get(CMSAttributes.messageDigest);

        assertNotNull(messageDigest);
        assertEquals(1, messageDigest.getAttrValues().size());
        assertNotNull(messageDigest.getAttrValues().getObjectAt(0));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.3
     */
    @Test
    public void shouldCmsObjectHaveSigningTimeSignedAttribute() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute signingTimeAttr = attributeTable.get(CMSAttributes.signingTime);

        assertNotNull(signingTimeAttr);
        assertEquals(1, signingTimeAttr.getAttrValues().size());
        ASN1UTCTime signingTime = (ASN1UTCTime) signingTimeAttr.getAttrValues().getObjectAt(0);
        assertEquals(this.signingTime, signingTime.getDate().getTime());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.4
     */
    @Test
    public void shouldCmsObjectHaveNoBinarySigningTimeSignedAttribute() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute contentType = attributeTable.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.46"));

        assertNull(contentType);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.5
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldCmsObjectHaveRSASignatureAlgorithm() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertEquals(SHA256WITHRSA_ENCRYPTION_OID, signer.getEncryptionAlgOID());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.6
     */
    @Test
    public void shouldCmsObjectHaveValidSignature() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertNotNull(signer.getSignature());
        assertTrue("signature verify", signer.verify(new JcaSignerInfoVerifierBuilder(BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER).build(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.7
     */
    @Test
    public void shouldCmsObjectHaveNoUnsignedAttribute() throws Exception {
        Collection<?> signers = signedDataParser.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertNull(signer.getUnsignedAttributes());
    }
}
