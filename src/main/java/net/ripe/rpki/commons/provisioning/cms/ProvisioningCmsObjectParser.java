package net.ripe.rpki.commons.provisioning.cms;

import com.google.common.io.ByteSource;
import lombok.AccessLevel;
import lombok.Setter;
import net.ripe.rpki.commons.crypto.cms.SigningInformationUtil;
import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadParser;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateParser;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.StoreException;
import org.joda.time.DateTime;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.ALLOWED_SIGNATURE_ALGORITHM_OIDS;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public class ProvisioningCmsObjectParser {

    private static final BcDigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER = new BcDigestCalculatorProvider();

    private static final ASN1ObjectIdentifier PROVISIONING_OBJECT_OID_STRING = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.28");
    private static final int CMS_OBJECT_SIGNER_VERSION = 3;
    private static final int CMS_OBJECT_VERSION = 3;

    private byte[] encoded;

    private X509Certificate cmsCertificate;

    private Collection<X509Certificate> caCertificates = new HashSet<X509Certificate>();

    private X509CRL crl;

    private CMSSignedDataParser sp;

    private ValidationResult validationResult;

    private String location;
    private AbstractProvisioningPayload payload;

    @Setter(AccessLevel.PRIVATE)
    private DateTime signingTime;

    public ProvisioningCmsObjectParser() {
        this(ValidationResult.withLocation("n/a"));
    }

    public ProvisioningCmsObjectParser(ValidationResult validationResult) {
        this.validationResult = validationResult;
    }

    public ValidationResult getValidationResult() {
        return validationResult;
    }

    public void parseCms(String location, byte[] encoded) {
        this.location = location;
        this.encoded = encoded;
        validationResult.setLocation(new ValidationLocation(location));

        try{
            sp = new CMSSignedDataParser(DIGEST_CALCULATOR_PROVIDER, encoded);
        } catch (CMSException e) {
            validationResult.rejectIfFalse(false, CMS_DATA_PARSING, extractMessages(e));
            return;
        }
        validationResult.rejectIfFalse(true, CMS_DATA_PARSING);

        verifyVersionNumber();
        verifyDigestAlgorithm(encoded);
        verifyContentType();
        parseContent();

        parseCertificates();
        parseCmsCrl();
        verifySignerInfos();
    }

    private String extractMessages(CMSException e) {
        Throwable t = e;
        final List<String> messages = new ArrayList<String>();
        while (t != null && !messages.contains(t.getMessage())) {
            messages.add(t.getMessage());
            t = t.getCause();
        }
        return String.join(", reason: ", messages);
    }

    public ProvisioningCmsObject getProvisioningCmsObject() {
        if (validationResult.hasFailures()) {
            throw new ProvisioningCmsObjectParserException("provisioning cms object validation failed: " + validationResult.getFailuresForCurrentLocation());
        }
        return new ProvisioningCmsObject(encoded, cmsCertificate, caCertificates, crl, payload, signingTime);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.1
     */
    private void verifyVersionNumber() {
        validationResult.rejectIfFalse(sp.getVersion() == CMS_OBJECT_VERSION, CMS_SIGNED_DATA_VERSION);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.2
     */
    private void verifyDigestAlgorithm(byte[] data) {
        validationResult.rejectIfFalse(CMSSignedGenerator.DIGEST_SHA256.equals(getDigestAlgorithmOidFromEncodedCmsObject(data).getAlgorithm().getId()), CMS_SIGNED_DATA_DIGEST_ALGORITHM);
    }

    private AlgorithmIdentifier getDigestAlgorithmOidFromEncodedCmsObject(byte[] data) {
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(data));
        ContentInfo info;
        try {
            info = ContentInfo.getInstance(in.readObject());
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object content info", e);
        }
        SignedData signedData = SignedData.getInstance(info.getContent());
        ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
        ASN1Encodable object = digestAlgorithms.getObjectAt(0);
        return AlgorithmIdentifier.getInstance(object.toASN1Primitive());
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.1
     */
    private void verifyContentType() {
        validationResult.rejectIfFalse(PROVISIONING_OBJECT_OID_STRING.equals(sp.getSignedContent().getContentType()), CMS_CONTENT_TYPE);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.3.2
     */
    private void parseContent() {
        try {
            ByteSource byteSource = new ByteSource() {
                @Override
                public InputStream openStream() {
                    return sp.getSignedContent().getContentStream();
                }
            };
            final String payloadXml = byteSource.asCharSource(StandardCharsets.UTF_8).read();
            payload = PayloadParser.parse(payloadXml, validationResult);

            validationResult.rejectIfFalse(true, CMS_CONTENT_PARSING);
        } catch (IOException e) {
            validationResult.rejectIfFalse(false, CMS_CONTENT_PARSING);
        }
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.4
     */
    private void parseCertificates() {
        Collection<? extends Certificate> certificates = extractCertificates(sp);
        if (!validationResult.rejectIfNull(certificates, GET_CERTS_AND_CRLS)) {
            return;
        }

        for (Certificate cert : certificates) {
            if (!validationResult.rejectIfFalse(cert instanceof X509Certificate, CERT_IS_X509CERT)) {
                continue;
            }
            processX509Certificate((X509Certificate) cert);
        }
    }

    private void processX509Certificate(X509Certificate certificate) {
        if (isEndEntityCertificate(certificate)) {
            if (cmsCertificate == null) {
                cmsCertificate = parseCmsCertificate(certificate);
                validationResult.rejectIfFalse(true, CERT_IS_EE_CERT);
                validationResult.rejectIfNull(X509CertificateUtil.getSubjectKeyIdentifier(cmsCertificate) != null, CERT_HAS_SKI);
            } else {
                validationResult.rejectIfFalse(false, ONLY_ONE_EE_CERT_ALLOWED);
            }
        } else {
            caCertificates.add(certificate);
        }
    }

    private X509Certificate parseCmsCertificate(X509Certificate certificate) {
        ProvisioningCmsCertificateParser parser = new ProvisioningCmsCertificateParser();
        try {
            parser.parse(ValidationResult.withLocation(location), certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
        return parser.getCertificate().getCertificate();
    }

    private boolean isEndEntityCertificate(X509Certificate certificate) {
        try {
            byte[] basicConstraintsExtension = certificate.getExtensionValue(Extension.basicConstraints.getId());
            if (basicConstraintsExtension == null) {
                /**
                 * If the basic constraints extension is not present [...] then the certified public key MUST NOT be used
                 * to verify certificate signatures.
                 *  http://tools.ietf.org/html/rfc5280#section-4.2.1.9
                 */
                return true;
            }
            BasicConstraints constraints = BasicConstraints.getInstance(JcaX509ExtensionUtils.parseExtensionValue(basicConstraintsExtension));
            return !constraints.isCA();
        } catch (IOException e) {
            throw new ProvisioningCmsObjectParserException("error while reading cms object certificate", e);
        }
    }

    private Collection<? extends Certificate> extractCertificates(CMSSignedDataParser sp) {
        try {
            return BouncyCastleUtil.extractCertificates(sp);
        } catch (CMSException e) {
            return null;
        } catch (StoreException e) {
            return null;
        } catch (CertificateException e) {
            return null;
        }
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.5
     */
    private void parseCmsCrl() {
        List<? extends X509CRL> crls = extractCrl(sp);
        if (!validationResult.rejectIfNull(crls, GET_CERTS_AND_CRLS)) {
            return;
        }

        if (!validationResult.rejectIfFalse(crls.size() == 1, ONLY_ONE_CRL_ALLOWED)) {
            return;
        }

        CRL x509Crl = crls.get(0);
        if (validationResult.rejectIfFalse(x509Crl instanceof X509CRL, CRL_IS_X509CRL)) {
            crl = (X509CRL) x509Crl;
        }
    }

    private List<? extends X509CRL> extractCrl(CMSSignedDataParser sp) {
        try {
            return BouncyCastleUtil.extractCrls(sp);
        } catch (CMSException e) {
            return null;
        } catch (StoreException e) {
            return null;
        } catch (CRLException e) {
            return null;
        }
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6
     */
    private void verifySignerInfos() {
        SignerInformationStore signerStore = getSignerStore();
        if (!validationResult.rejectIfNull(signerStore, GET_SIGNER_INFO)) {
            return;
        }

        Collection<?> signers = signerStore.getSigners();
        validationResult.rejectIfFalse(signers.size() == 1, ONLY_ONE_SIGNER);

        SignerInformation signer = (SignerInformation) signers.iterator().next();
        verifySignerVersion(signer);
        verifySubjectKeyIdentifier(signer);
        verifyDigestAlgorithm(signer);
        verifySignedAttributes(signer);
        verifyEncryptionAlgorithm(signer);
        verifySignature(signer);
        verifyUnsignedAttributes(signer);
    }

    private SignerInformationStore getSignerStore() {
        SignerInformationStore signerStore;
        try {
            signerStore = sp.getSignerInfos();
        } catch (CMSException e) {
            signerStore = null;
        }
        return signerStore;
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.1
     */
    private void verifySignerVersion(SignerInformation signer) {
        validationResult.rejectIfFalse(signer.getVersion() == CMS_OBJECT_SIGNER_VERSION, CMS_SIGNER_INFO_VERSION);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.2
     */
    private void verifySubjectKeyIdentifier(SignerInformation signer) {
        SignerId sid = signer.getSID();
        validationResult.rejectIfFalse(Arrays.equals(X509CertificateUtil.getSubjectKeyIdentifier(cmsCertificate), sid.getSubjectKeyIdentifier()), CMS_SIGNER_INFO_SKI);
        validationResult.rejectIfFalse(sid.getIssuer() == null && sid.getSerialNumber() == null, CMS_SIGNER_INFO_SKI_ONLY);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.3
     */
    private void verifyDigestAlgorithm(SignerInformation signer) {
        validationResult.rejectIfFalse(CMSSignedGenerator.DIGEST_SHA256.equals(signer.getDigestAlgOID()), CMS_SIGNER_INFO_DIGEST_ALGORITHM);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4
     */
    private void verifySignedAttributes(SignerInformation signer) {
        AttributeTable attributeTable = signer.getSignedAttributes();
        if (!validationResult.rejectIfNull(attributeTable, SIGNED_ATTRS_PRESENT)) {
            return;
        }

        verifyContentType(attributeTable);
        verifyMessageDigest(attributeTable);
        verifySigningTime(signer);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.1
     */
    private void verifyContentType(AttributeTable attributeTable) {
        Attribute contentType = attributeTable.get(CMSAttributes.contentType);
        if (!validationResult.rejectIfNull(contentType, CONTENT_TYPE_ATTR_PRESENT)) {
            return;
        }
        if (!validationResult.rejectIfFalse(contentType.getAttrValues().size() == 1, CONTENT_TYPE_VALUE_COUNT)) {
            return;
        }
        validationResult.rejectIfFalse(PROVISIONING_OBJECT_OID_STRING.equals(contentType.getAttrValues().getObjectAt(0)), CONTENT_TYPE_VALUE);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.4.2
     */
    private void verifyMessageDigest(AttributeTable attributeTable) {
        Attribute messageDigest = attributeTable.get(CMSAttributes.messageDigest);
        if (!validationResult.rejectIfNull(messageDigest, MSG_DIGEST_ATTR_PRESENT)) {
            return;
        }
        if (!validationResult.rejectIfFalse(messageDigest.getAttrValues().size() == 1, MSG_DIGEST_VALUE_COUNT)) {
            return;
        }
    }

    /**
     * https://datatracker.ietf.org/doc/html/rfc6492#section-3.1.1.6.4 and
     * https://datatracker.ietf.org/doc/html/rfc6492#section-3.1.1.6.4.4
     *
     * Either one of the signing-time or the binary-signing-time attributes,
     * or both attributes, MUST be present.
     * => implemented here. Other checks are in {@link SigningInformationUtil#extractSigningTime(net.ripe.rpki.commons.validation.ValidationResult, org.bouncycastle.cms.SignerInformation)}
     */
    private void verifySigningTime(SignerInformation signer) {
        final SigningInformationUtil.SigningTimeResult signingTimeResult = SigningInformationUtil.extractSigningTime(validationResult, signer);

        if (!validationResult.rejectIfFalse(signingTimeResult.optionalSigningTime.isPresent(), SIGNING_TIME_ATTR_PRESENT)) {
            return;
        }
        this.signingTime = signingTimeResult.getOptionalSigningTime().get();
    }

    /**
     * https://tools.ietf.org/html/rfc6492#section-3.1.1.6.5
     * https://tools.ietf.org/html/rfc7935#section-2
     */
    private void verifyEncryptionAlgorithm(SignerInformation signer) {
        validationResult.rejectIfFalse(ALLOWED_SIGNATURE_ALGORITHM_OIDS.contains(signer.getEncryptionAlgOID()), ENCRYPTION_ALGORITHM);
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.6
     */
    private void verifySignature(SignerInformation signer) {
        String errorMessage = null;
        try {
            final SignerInformationVerifier verifier = new JcaSignerInfoVerifierBuilder(
                BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER).build(cmsCertificate.getPublicKey());

            validationResult.rejectIfFalse(signer.verify(verifier), SIGNATURE_VERIFICATION);
        } catch (CMSException | OperatorCreationException e) {
            errorMessage = String.valueOf(e.getMessage());
        }

        if (errorMessage != null) {
            validationResult.rejectIfFalse(false, SIGNATURE_VERIFICATION, errorMessage);
        }
    }

    /**
     * http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.1.6.7
     */
    private void verifyUnsignedAttributes(SignerInformation signer) {
        validationResult.rejectIfFalse(signer.getUnsignedAttributes() == null, UNSIGNED_ATTRS_OMITTED);
    }
}
