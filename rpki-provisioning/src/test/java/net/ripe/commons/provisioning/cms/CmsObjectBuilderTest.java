package net.ripe.commons.provisioning.cms;

import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateTest.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

public class CmsObjectBuilderTest {

    private CmsObjectBuilder subject;
    private CmsObject cmsObject;
    private static final X509CRL CRL = generateCrl();
    private static final X509Certificate EE_CERT = generateEECertificate();


    @Before
    public void setUp() throws Exception {
        subject =  new CmsObjectBuilder();

        subject.withCertificate(EE_CERT);
        subject.withCrl(CRL);
        subject.withSignatureProvider("SunRsaSign");
        cmsObject = subject.build(TEST_KEY_PAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldForceCertificate() throws CMSException {
        subject = new CmsObjectBuilder();
        subject.withCrl(CRL);
        subject.withSignatureProvider("SunRsaSign");
        subject.build(TEST_KEY_PAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldForceCrl() throws CMSException {
        subject = new CmsObjectBuilder();
        subject.withCertificate(EE_CERT);
        subject.withSignatureProvider("SunRsaSign");
        subject.build(TEST_KEY_PAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldForceSignatureProvider() throws CMSException {
        subject = new CmsObjectBuilder();
        subject.withCertificate(EE_CERT);
        subject.withCrl(CRL);
        subject.build(TEST_KEY_PAIR.getPrivate());
    }

    @Test
    public void shouldBuildValidCmsObject() throws Exception {
        new CMSSignedDataParser(cmsObject.getEncodedContent());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectVersionNumber() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        assertEquals(3, sp.getVersion());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.2
     */
    @Test
    public void shouldCmsObjectHaveCorrectDigestAlgorithm() throws CMSException {
        // TODO:
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.1
     */
    @Test
    public void shouldCmsObjectHaveCorrectContentType() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        assertEquals(CmsObject.CONTENT_TYPE, sp.getSignedContent().getContentType());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.2
     */
    @Test
    public void shouldCmsObjectHavePayload() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        InputStream signedContentStream = sp.getSignedContent().getContentStream();
        ASN1InputStream asn1InputStream = new ASN1InputStream(signedContentStream);
        DERObject derObject = asn1InputStream.readObject();

        assertNull(asn1InputStream.readObject()); //only one signed object

        asn1InputStream.close();

        DEROctetString derString = (DEROctetString)derObject;
        assertEquals("Hello", new String(derString.getOctets()));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.4
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedCertificate() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", (String)null);
        Collection<? extends Certificate> certificates = certificatesAndCRLs.getCertificates(null);

        assertNotNull(certificates);
        assertFalse(certificates.isEmpty());
        assertEquals(EE_CERT, certificates.iterator().next());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.5
     */
    @Test
    public void shouldCmsObjectHaveEmbeddedCrl() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        CertStore certificatesAndCRLs = sp.getCertificatesAndCRLs("Collection", (String)null);
        Collection<? extends java.security.cert.CRL> crls = certificatesAndCRLs.getCRLs(null);

        assertNotNull(crls);
        //FIXME:
//        assertFalse(crls.isEmpty());
//        assertEquals(CRL, crls.iterator().next());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6
     */
    @Test
    public void shouldCmsObjectHaveOnlyOneSigner() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
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
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
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
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        byte[] extensionValue = EE_CERT.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
        byte[] ski = SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();

        assertArrayEquals(new DEROctetString(ski).getEncoded(), signer.getSID().getSubjectKeyIdentifier());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    @Test
    public void shouldCmsObjectHaveSubjectKeyIdentifierOnly() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
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
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertEquals(CmsObject.DIGEST_ALGORITHM_OID, signer.getDigestAlgOID());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.5
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldCmsObjectHaveRSASignatureAlgorithm() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertEquals(CMSSignedGenerator.ENCRYPTION_RSA, signer.getEncryptionAlgOID());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.6
     */
    @Test
    public void shouldCmsObjectHaveValidSignature() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertNotNull(signer.getSignature());
        signer.verify(EE_CERT.getPublicKey(), "SunRsaSign");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.7
     */
    @Test
    public void shouldCmsObjectHaveNoUnsignedAttribute() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(cmsObject.getEncodedContent());
        sp.getSignedContent().drain();
        Collection<?> signers = sp.getSignerInfos().getSigners();
        SignerInformation signer =  (SignerInformation) signers.iterator().next();

        assertNull(signer.getUnsignedAttributes());
    }










    private static X509CRL generateCrl() {
        try {
            X509V2CRLGenerator generator = createCrlGenerator();
            return generator.generate(TEST_KEY_PAIR.getPrivate(), "SunRsaSign");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X509V2CRLGenerator createCrlGenerator() throws IOException {
        X509V2CRLGenerator generator = new X509V2CRLGenerator();
        generator.setIssuerDN(TEST_PROVISIONING_IDENTITY_CERTIFICATE.getCertificate().getIssuerX500Principal());
        generator.setThisUpdate(TEST_PROVISIONING_IDENTITY_CERTIFICATE.getCertificate().getNotBefore());
        generator.setNextUpdate(TEST_PROVISIONING_IDENTITY_CERTIFICATE.getCertificate().getNotAfter());
        generator.setSignatureAlgorithm("SHA256withRSA");
        generator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, AuthorityKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(TEST_PROVISIONING_IDENTITY_CERTIFICATE.getCertificate().getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId()))).getKeyIdentifier());
        generator.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.ONE));
        return generator;
    }

    private static X509Certificate generateEECertificate() {
        KeyPair keyPair = ProvisioningKeyPairGenerator.generate();

        try {
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.setNotBefore(new Date(new DateTime().minusDays(7).getMillis()));
            generator.setNotAfter(new Date(new DateTime().plusDays(7).getMillis()));
            generator.setIssuerDN(new X500Principal("CN=nl.bluelight"));
            generator.setSerialNumber(BigInteger.TEN);
            generator.setPublicKey(keyPair.getPublic());
            generator.setSignatureAlgorithm("SHA256withRSA");
            generator.setSubjectDN(new X500Principal("CN=nl.bluelight.ee"));

            generator.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(keyPair.getPublic()));
            generator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(TEST_KEY_PAIR.getPublic()));
            generator.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            //        generator.addExtension(X509Extensions.CertificatePolicies, true, new DERSequence(new DERObjectIdentifier("1.3.6.1.5.5.7.14.2")));
            //TODO: check and add other extensions

            return generator.generate(TEST_KEY_PAIR.getPrivate(), "SunRsaSign");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
