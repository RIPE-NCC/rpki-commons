package net.ripe.commons.provisioning.cms;

import net.ripe.commons.certification.x509cert.X509CertificateUtil;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;

import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static net.ripe.commons.provisioning.ProvisioningObjectMother.CRL;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT;
import static org.bouncycastle.cms.CMSSignedGenerator.DIGEST_SHA256;
import static org.bouncycastle.cms.CMSSignedGenerator.ENCRYPTION_RSA;
import static org.junit.Assert.*;

public class ProvisioningCmsObjectBuilderTest {

    private ProvisioningCmsObjectBuilder subject;
    private ProvisioningCmsObject cmsObject;
    private long signingTime;

    @Before
    public void setUp() throws Exception {
        subject = new ProvisioningCmsObjectBuilder()
                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                        .withCrl(CRL)
                        .withPayloadContent(ProvisioningObjectMother.PAYLOAD)
                        .withCaCertificate(TEST_IDENTITY_CERT.getCertificate());

        signingTime = new DateTime().getMillis() / 1000 * 1000; // truncate milliseconds
        DateTimeUtils.setCurrentMillisFixed(signingTime);
        cmsObject = subject.build(EE_KEYPAIR.getPrivate());
        DateTimeUtils.setCurrentMillisSystem();
    }

    public static ProvisioningCmsObject createProvisioningCmsObject() {
        ProvisioningCmsObjectBuilder subject =  new ProvisioningCmsObjectBuilder()
                                                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                                                        .withCrl(CRL)
                                                        .withPayloadContent(ProvisioningObjectMother.PAYLOAD)
                                                        .withCaCertificate(TEST_IDENTITY_CERT.getCertificate());

        return subject.build(EE_KEYPAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldForceCertificate() throws CMSException {
        subject = new ProvisioningCmsObjectBuilder()
                        .withPayloadContent(ProvisioningObjectMother.PAYLOAD)
                        .withCrl(CRL)
                        .withCaCertificate(TEST_IDENTITY_CERT.getCertificate());
        subject.build(EE_KEYPAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldForceCrl() throws CMSException {
        subject = new ProvisioningCmsObjectBuilder()
                        .withPayloadContent(ProvisioningObjectMother.PAYLOAD)
                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                        .withCaCertificate(TEST_IDENTITY_CERT.getCertificate());
        subject.build(EE_KEYPAIR.getPrivate());
    }

    @Test
    public void shouldNotForceIdentityCertificate() throws CMSException {
        ProvisioningCmsObjectBuilder subject =  new ProvisioningCmsObjectBuilder()
                                                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                                                        .withCrl(CRL)
                                                        .withPayloadContent(ProvisioningObjectMother.PAYLOAD);
        subject.build(EE_KEYPAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldForcePayload() throws CMSException {
        subject = new ProvisioningCmsObjectBuilder()
                        .withCrl(ProvisioningObjectMother.CRL)
                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                        .withCaCertificate(TEST_IDENTITY_CERT.getCertificate());
        subject.build(EE_KEYPAIR.getPrivate());
    }

    @Test
    public void shouldBuildValidCmsObject() throws Exception {
        new CMSSignedDataParser(cmsObject.getEncoded());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectVersionNumber() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        assertEquals(3, sp.getVersion());
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
        DEREncodable derObject = digestAlgorithms.getObjectAt(0);
        AlgorithmIdentifier algorithmId = AlgorithmIdentifier.getInstance(derObject.getDERObject());

        assertEquals(DIGEST_SHA256, algorithmId.getObjectId().getId());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectContentType() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        assertEquals("1.2.840.113549.1.9.16.1.28", sp.getSignedContent().getContentType());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.2
     */
    @Test
    public void shouldCmsObjectHavePayload() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        InputStream signedContentStream = sp.getSignedContent().getContentStream();
        ASN1InputStream asn1InputStream = new ASN1InputStream(signedContentStream);
        DERObject derObject = asn1InputStream.readObject();

        assertNull(asn1InputStream.readObject()); //only one signed object

        asn1InputStream.close();

        DEROctetString derString = (DEROctetString)derObject;
        assertEquals(ProvisioningObjectMother.PAYLOAD, new String(derString.getOctets()));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.4
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedEECertificate() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", (String) null);
        Collection<? extends Certificate> certificates = certificatesAndCRLs.getCertificates(null);

        assertNotNull(certificates);
        assertFalse(certificates.isEmpty());

        certificates = new ArrayList<Certificate>(certificates);
        assertTrue(certificates.contains(TEST_CMS_CERT.getCertificate()));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.4
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedIdentityCertificate() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", (String) null);
        Collection<? extends Certificate> certificates = certificatesAndCRLs.getCertificates(null);

        assertNotNull(certificates);
        assertFalse(certificates.isEmpty());
        assertEquals(2, certificates.size());

        certificates = new ArrayList<Certificate>(certificates);
        assertTrue(certificates.contains(TEST_IDENTITY_CERT.getCertificate()));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.5
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedCrl() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", (String) null);
        Collection<? extends java.security.cert.CRL> crls = certificatesAndCRLs.getCRLs(null);

        assertNotNull(crls);
        assertFalse(crls.isEmpty());
        assertEquals(CRL, crls.iterator().next());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6
     */
    @Test
    public void shouldCmsObjectHaveOnlyOneSigner() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();

        assertNotNull(signers);
        assertEquals(1, signers.size());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.1
     */
    @Test
    public void shouldCmsObjectSignerVersionBeCorrect() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();
        assertEquals(3, signer.getVersion());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    @Test
    public void shouldCmsObjectHaveCorrectSubjectKeyIdentifier() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertArrayEquals(new DEROctetString(X509CertificateUtil.getSubjectKeyIdentifier(TEST_CMS_CERT.getCertificate())).getEncoded(), signer.getSID().getSubjectKeyIdentifier());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    @Test
    public void shouldCmsObjectHaveSubjectKeyIdentifierOnly() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertNull(signer.getSID().getIssuer());
        assertNull(signer.getSID().getSerialNumber());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.3
     */
    @Test
    public void shouldCmsObjectHaveCorrectDigestAlgorithmOID() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertEquals(DIGEST_SHA256, signer.getDigestAlgOID());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4
     */
    @Test
    public void shouldCmsObjectHaveSignedAttributes() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertNotNull(signer.getSignedAttributes());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectContentTypeSignedAttribute() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute contentType = attributeTable.get(CMSAttributes.contentType);

        assertNotNull(contentType);
        assertEquals(1, contentType.getAttrValues().size());
        assertEquals(new DERObjectIdentifier("1.2.840.113549.1.9.16.1.28"), contentType.getAttrValues().getObjectAt(0));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.2
     */
    @Test
    public void shouldCmsObjectHaveCorrectMessageDigestSignedAttribute() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();
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
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute signingTimeAttr = attributeTable.get(CMSAttributes.signingTime);

        assertNotNull(signingTimeAttr);
        assertEquals(1, signingTimeAttr.getAttrValues().size());
        DERUTCTime signingTime = (DERUTCTime) signingTimeAttr.getAttrValues().getObjectAt(0);
        assertEquals(this.signingTime, signingTime.getDate().getTime());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.4
     */
    @Test
    public void shouldCmsObjectHaveNoBinarySigningTimeSignedAttribute() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();
        AttributeTable attributeTable = signer.getSignedAttributes();
        Attribute contentType = attributeTable.get(new DERObjectIdentifier("1.2.840.113549.1.9.16.2.46"));

        assertNull(contentType);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.5
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldCmsObjectHaveRSASignatureAlgorithm() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertEquals(ENCRYPTION_RSA, signer.getEncryptionAlgOID());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.6
     */
    @Test
    public void shouldCmsObjectHaveValidSignature() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertNotNull(signer.getSignature());
        signer.verify(TEST_CMS_CERT.getCertificate(), DEFAULT_SIGNATURE_PROVIDER);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.7
     */
    @Test
    public void shouldCmsObjectHaveNoUnsignedAttribute() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncoded());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer = (SignerInformation) signers.iterator().next();

        assertNull(signer.getUnsignedAttributes());
    }
}
