package net.ripe.commons.provisioning.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import net.ripe.commons.certification.x509cert.X509CertificateUtil;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public abstract class ProvisioningCmsObjectParser {

    private static final int CMS_OBJECT_SIGNER_VERSION = 3;

    private static final int CMS_OBJECT_VERSION = 3;

    private static final String SUN_RSA_SIGN = "SunRsaSign";

    private byte[] encoded;

    private X509Certificate certificate;

    private CMSSignedDataParser sp;


    public ProvisioningCmsObjectParser(byte[] encoded) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;
    }

    public void parseCms() {
        try {
            sp = new CMSSignedDataParser(encoded);
        } catch (CMSException e) {
            throw new ProvisioningCmsObjectParserException("invalid cms object", e);
        }

        verifyVersionNumber();
        verifyDigestAlgorithm(encoded);
        verifyContentType();
        parseContent();

        parseCmsCertificate();
        verifySignerInfos();
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.1
     */
    private void verifyVersionNumber() {
        Validate.isTrue(sp.getVersion() == CMS_OBJECT_VERSION, "invalid cms object version number");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.2
     */
    private void verifyDigestAlgorithm(byte[] data) {
        Validate.isTrue(CMSSignedGenerator.DIGEST_SHA256.equals(getDigestAlgorithmOidFromEncodedCmsObject(data).getObjectId().getId()), "invalis cms object digest algorithm");
    }

    private AlgorithmIdentifier getDigestAlgorithmOidFromEncodedCmsObject(byte[] data) {
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(data));
        ContentInfo info = null;
        try {
            info = ContentInfo.getInstance(in.readObject());
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object content info", e);
        }
        SignedData signedData = SignedData.getInstance(info.getContent());
        ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
        DEREncodable derObject = digestAlgorithms.getObjectAt(0);
        return AlgorithmIdentifier.getInstance(derObject.getDERObject());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.1
     */
    private void verifyContentType() {
        Validate.isTrue("1.2.840.113549.1.9.16.1.28".equals(sp.getSignedContent().getContentType()));
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.2
     */
    private void parseContent() {
        InputStream signedContentStream = sp.getSignedContent().getContentStream();
        ASN1InputStream asn1InputStream = new ASN1InputStream(signedContentStream);

        try {
            decodeContent(asn1InputStream.readObject());
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("cannot decode cms object signed content", e);
        }

        try {
            Validate.isTrue(asn1InputStream.readObject() == null, "more than one signed object in cms object signed content");
            asn1InputStream.close();
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object signed content", e);
        }
    }

    protected abstract void decodeContent(DEREncodable encoded);

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.4
     */
    private void parseCmsCertificate() {
        Collection<? extends Certificate> certificates = extractCertificate(sp);
        Validate.notNull(certificates, "error while extracting the certificate from the cms object");
        Validate.notEmpty(certificates, "cms object must contain one certificate");
        Validate.isTrue(certificates.size() == 1, "cms object must contain exactly one certificate");
        Certificate cert = certificates.iterator().next();
        Validate.isTrue(cert instanceof X509Certificate, "cms object certificate must be X509Certificate");

        certificate = (X509Certificate) cert;

        Validate.isTrue(X509CertificateUtil.getSubjectKeyIdentifier(certificate) != null, "cms object certificate must have subject key identifier");
        Validate.isTrue(isEndEntityCertificate(certificate), "cms object certificate must be end entity certificate");
    }

    private boolean isEndEntityCertificate(X509Certificate certificate) {
        try {
            byte[] basicConstraintsExtension = certificate.getExtensionValue(X509Extensions.BasicConstraints.getId());
            if (basicConstraintsExtension == null) {
                return false;
            }
            BasicConstraints constraints = BasicConstraints.getInstance(X509ExtensionUtil.fromExtensionValue(basicConstraintsExtension));
            return ! constraints.isCA();
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object certificate", e);
        }
    }

    private Collection<? extends Certificate> extractCertificate(CMSSignedDataParser sp) {
        Collection<? extends Certificate> certificates;
        try {
            CertStore certs;
            certs = sp.getCertificatesAndCRLs("Collection", (String) null);
            certificates = certs.getCertificates(null);
        } catch (NoSuchAlgorithmException e) {
            certificates = null;
        } catch (NoSuchProviderException e) {
            certificates = null;
        } catch (CMSException e) {
            certificates = null;
        } catch (CertStoreException e) {
            certificates = null;
        }
        return certificates;
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6
     */
    private void verifySignerInfos() {
        Collection<?> signers = null;
        try {
            signers = sp.getSignerInfos().getSigners();
        } catch (CMSException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object signers", e);
        }

        Validate.notNull(signers, "one signer is required for the cms object");
        Validate.isTrue(signers.size() == 1, "only one signer allowed in the cms object");

        SignerInformation signer =  (SignerInformation) signers.iterator().next();
        verifySignerVersion(signer);
        verifySubjectKeyIdentifier(signer);
        verifyDigestAlgorithm(signer);
        verifySignedAttributes(signer);
        verifyEncryptionAlgorithm(signer);
        verifySignature(signer);
        verifyUnsignedAttributes(signer);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.1
     */
    private void verifySignerVersion(SignerInformation signer) {
        Validate.isTrue(signer.getVersion() == CMS_OBJECT_SIGNER_VERSION, "invalid cms object signer version number");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    private void verifySubjectKeyIdentifier(SignerInformation signer) {
        try {
            Validate.isTrue(Arrays.equals(new DEROctetString(X509CertificateUtil.getSubjectKeyIdentifier(certificate)).getEncoded(), signer.getSID().getSubjectKeyIdentifier()), "subject key identifier on the cms object and its ee certificate must match");
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object certificate subject key identifier", e);
        }
        Validate.isTrue(signer.getSID().getIssuer() == null, "cms object signer identifier must contain subject key identifier only");
        Validate.isTrue(signer.getSID().getSerialNumber() == null, "cms object signer identifier must contain subject key identifier only");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.3
     */
    private void verifyDigestAlgorithm(SignerInformation signer) {
        Validate.isTrue(signer.getDigestAlgOID().equals(CMSSignedGenerator.DIGEST_SHA256), "incorrect digest algorithm");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4
     */
    private void verifySignedAttributes(SignerInformation signer) {
        AttributeTable attributeTable = signer.getSignedAttributes();
        Validate.notNull(attributeTable, "cms object must have signed attributes");

        verifyContentType(attributeTable);
        verifyMessageDigest(attributeTable);
        verifySigningTime(attributeTable);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.1
     */
    private void verifyContentType(AttributeTable attributeTable) {
        Attribute contentType = attributeTable.get(CMSAttributes.contentType);
        Validate.notNull(contentType, "cms object must have content type signed attribute");
        Validate.isTrue(contentType.getAttrValues().size() == 1, "cms object content type signed attribute must have only 1 value");
        Validate.isTrue(new DERObjectIdentifier("1.2.840.113549.1.9.16.1.28").equals(contentType.getAttrValues().getObjectAt(0)), "incorrect cms content type");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.2
     */
    private void verifyMessageDigest(AttributeTable attributeTable) {
        Attribute messageDigest = attributeTable.get(CMSAttributes.messageDigest);
        Validate.notNull(messageDigest, "cms object must have message digest signed attribute");
        Validate.isTrue(messageDigest.getAttrValues().size() == 1, "cms object message digest signed attribute must have only 1 value");
        Validate.notNull(messageDigest.getAttrValues().getObjectAt(0) != null, "cms object must have message digest signed attribute value");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.3
     */
    private void verifySigningTime(AttributeTable attributeTable) {
        Attribute signingTime = attributeTable.get(CMSAttributes.signingTime);
        Validate.notNull(signingTime, "cms object must have signing time signed attribute");
        Validate.isTrue(signingTime.getAttrValues().size() == 1, "cms object signing time signed attribute must have only 1 value");
        Validate.notNull(signingTime.getAttrValues().getObjectAt(0) != null, "cms object must have signing time signed attribute value");
    }

    private void verifyEncryptionAlgorithm(SignerInformation signer) {
        /**
         * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.5
         * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
         */
        Validate.isTrue(CMSSignedGenerator.ENCRYPTION_RSA.equals(signer.getEncryptionAlgOID()), "signature algorith must be RSA");
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.6
     */
    private void verifySignature(SignerInformation signer) {
        Validate.notNull(signer.getSignature(), "cms object must have signature");
        try {
            Validate.isTrue(signer.verify(certificate, SUN_RSA_SIGN), "cms object signature verification failed");
        } catch (CertificateExpiredException e) {
            throw new ProvisioningCmsObjectParserException("cms object signature verification failed", e);
        } catch (CertificateNotYetValidException e) {
            throw new ProvisioningCmsObjectParserException("cms object signature verification failed", e);
        } catch (NoSuchAlgorithmException e) {
            throw new ProvisioningCmsObjectParserException("cms object signature verification failed", e);
        } catch (NoSuchProviderException e) {
            throw new ProvisioningCmsObjectParserException("cms object signature verification failed", e);
        } catch (CMSException e) {
            throw new ProvisioningCmsObjectParserException("cms object signature verification failed", e);
        }
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.7
     */
    private void verifyUnsignedAttributes(SignerInformation signer) {
        Validate.isTrue(signer.getUnsignedAttributes() == null, "cms object must not have unsigned attributes");
    }
}
