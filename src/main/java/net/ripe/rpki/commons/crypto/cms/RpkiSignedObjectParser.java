package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.StoreException;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.ALLOWED_SIGNATURE_ALGORITHM_OIDS;
import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.DIGEST_ALGORITHM_OID;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public abstract class RpkiSignedObjectParser {
    private static final int CMS_OBJECT_VERSION = 3;
    private static final int CMS_OBJECT_SIGNER_VERSION = 3;

    private byte[] encoded;

    private X509ResourceCertificate certificate;

    protected ASN1ObjectIdentifier contentType;

    private Optional<Instant> signingTime;

    private ValidationResult validationResult;

    public final void parse(String location, byte[] encoded) {
        parse(ValidationResult.withLocation(location), encoded);
    }

    public void parse(ValidationResult result, byte[] encoded) {
        this.validationResult = result;
        this.encoded = encoded;
        parseCms();
    }

    protected byte[] getEncoded() {
        return encoded;
    }

    public ValidationResult getValidationResult() {
        return validationResult;
    }

    protected X509ResourceCertificate getCertificate() {
        return certificate;
    }

    protected X509ResourceCertificate getResourceCertificate() {
        return certificate;
    }

    protected ASN1ObjectIdentifier getContentType() {
        return contentType;
    }

    protected @Nullable Instant getSigningTime() {
        return signingTime.orElse(null);
    }

    public void decodeRawContent(InputStream content) throws IOException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(content)) {
            decodeAsn1Content(asn1InputStream.readObject());

            validationResult.rejectIfFalse(asn1InputStream.readObject() == null, ONLY_ONE_SIGNED_OBJECT);
            validationResult.pass(CMS_CONTENT_PARSING);
        } catch (IOException e) {
            validationResult.error(CMS_CONTENT_PARSING);
        }
    }

    public void decodeAsn1Content(ASN1Encodable content) {
    }

    private void parseCms() {
        CMSSignedDataParser sp;
        try {
            sp = new CMSSignedDataParser(BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER, encoded);
            validationResult.pass(CMS_DATA_PARSING);
        } catch (CMSException e) {
            validationResult.error(CMS_DATA_PARSING);
            return;
        }

        parseContent(sp);
        parseCmsCertificate(sp);

        //https://datatracker.ietf.org/doc/html/rfc6488#section-3
        verifyContentType();
        verifyVersion(sp);
        verifyCrl(sp);

        if (certificate != null) {
            verifyCmsSigning(sp, certificate.getCertificate());
        }
    }

    protected void parseContent(CMSSignedDataParser sp) {
        final CMSTypedStream signedContent = sp.getSignedContent();
        contentType = signedContent.getContentType();


        try (InputStream signedContentStream = signedContent.getContentStream()) {
            decodeRawContent(signedContentStream);
            validationResult.pass(DECODE_CONTENT);
        } catch (IOException e) {
            validationResult.error(DECODE_CONTENT);
        }
    }

    /**
     * https://datatracker.ietf.org/doc/html/rfc6488#section-2
     */
    private void verifyContentType() {
        // CMSSignedDataParser does not check that the contentType of the ContentInfo is id-signeddata.
        // and does not allow you to access it => use the other CMS Signed Data implementation that is in BC.
        try {
            final CMSSignedData signedData = new CMSSignedData(encoded);
            validationResult.rejectIfFalse(CMSObjectIdentifiers.signedData.equals(signedData.toASN1Structure().getContentType()), CMS_CONTENT_TYPE);
        } catch (CMSException e) {
            validationResult.error(CMS_DATA_PARSING);
        }
    }


    /**
     * https://tools.ietf.org/html/rfc6488#section-2.1.1
     */
    private void verifyVersion(CMSSignedDataParser sp) {
        validationResult.rejectIfFalse(sp.getVersion() == CMS_OBJECT_VERSION, CMS_SIGNED_DATA_VERSION);
    }

    /**
     * https://tools.ietf.org/html/rfc6488#section-2.1.5
     */
    private void verifyCrl(CMSSignedDataParser sp) {
        List<? extends X509CRL> crls = extractCrl(sp);
        if (!validationResult.rejectIfNull(crls, GET_CERTS_AND_CRLS)) {
            return;
        }

        validationResult.rejectIfFalse(crls.isEmpty(), CMS_NO_CRL_ALLOWED);
    }

    private List<? extends X509CRL> extractCrl(CMSSignedDataParser sp) {
        try {
            return BouncyCastleUtil.extractCrls(sp);
        } catch (CMSException | StoreException | CRLException e) {
            return null;
        }
    }

    private void parseCmsCertificate(CMSSignedDataParser sp) {
        Collection<? extends Certificate> certificates = extractCertificate(sp);

        if (!validationResult.rejectIfNull(certificates, GET_CERTS_AND_CRLS)) {
            return;
        }
        if (!validationResult.rejectIfFalse(certificates.size() == 1, ONLY_ONE_EE_CERT_ALLOWED)) {
            return;
        }
        if (!validationResult.rejectIfFalse(certificates.iterator().next() instanceof X509Certificate, CERT_IS_X509CERT)) {
            return;
        }

        certificate = parseCertificate(certificates.iterator().next());
        if (validationResult.hasFailureForCurrentLocation()) {
            return;
        }

        validationResult.rejectIfFalse(certificate.isEe(), CERT_IS_EE_CERT);
        validationResult.rejectIfNull(certificate.getSubjectKeyIdentifier(), CERT_HAS_SKI);
    }

    private X509ResourceCertificate parseCertificate(Certificate certificate) {
        try {
            X509Certificate x509certificate = (X509Certificate) certificate;
            X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
            parser.parse(validationResult, x509certificate.getEncoded());
            return parser.isSuccess() ? parser.getCertificate() : null;
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException("cannot parse already decoded X509 certificate: " + e, e);
        }
    }

    private Collection<? extends Certificate> extractCertificate(CMSSignedDataParser sp) {
        try {
            return BouncyCastleUtil.extractCertificates(sp);
        } catch (CMSException | StoreException | CertificateException e) {
            return null;
        }
    }

    private void verifyCmsSigning(CMSSignedDataParser sp, X509Certificate certificate) {
        // Note: validationResult field is updated by methods used here.

        SignerInformation signer = extractSingleCmsSigner(sp);
        if (signer == null) {
            return;
        }

        if (!verifySigner(signer, certificate)) {
            return;
        }

        final SigningInformationUtil.SigningTimeResult st = SigningInformationUtil.extractSigningTime(validationResult, signer);
        if (!st.valid()) {
            return;
        }
        this.signingTime = st.optionalSigningTime();

        verifySignature(certificate, signer);
    }

    private SignerInformation extractSingleCmsSigner(CMSSignedDataParser sp) {
        SignerInformationStore signerStore = getSignerStore(sp);
        if (!validationResult.rejectIfNull(signerStore, GET_SIGNER_INFO)) {
            return null;
        }

        Collection<?> signers = signerStore.getSigners();
        if (validationResult.rejectIfFalse(signers.size() == 1, ONLY_ONE_SIGNER)) {
            return (SignerInformation) signers.iterator().next();
        } else {
            return null;
        }
    }

    private SignerInformationStore getSignerStore(CMSSignedDataParser sp) {
        try {
            return sp.getSignerInfos();
        } catch (CMSException | RuntimeException e) {
            return null; // Caller will validate that the SignerInformationStore is not null
        }
    }

    private boolean isAllowedSignedAttribute(Attribute signedAttribute) {
        ASN1ObjectIdentifier attributeOID = signedAttribute.getAttrType();

        //Check if the attribute is any of the allowed ones.
        return CMSAttributes.binarySigningTime.equals(attributeOID)
                || CMSAttributes.signingTime.equals(attributeOID)
                || CMSAttributes.contentType.equals(attributeOID)
                || CMSAttributes.messageDigest.equals(attributeOID);
    }

    private boolean verifyOptionalSignedAttributes(SignerInformation signer) {

        //To loop over
        ASN1EncodableVector signedAttributes = signer.getSignedAttributes().toASN1EncodableVector();
        Set<Attribute> seenAttributes = new HashSet<>();

        boolean allAttributesCorrect = true;
        for (int i = 0; i < signedAttributes.size(); i++) {
            Attribute signedAttribute = (Attribute)signedAttributes.get(i);
            if (!isAllowedSignedAttribute(signedAttribute)) {
                allAttributesCorrect = false;
                break;
            }

            // The signedAttrs element MUST include only a single instance of any particular attribute.
            if (!seenAttributes.add(signedAttribute)) {
                allAttributesCorrect = false;
                break;
            }

            // Additionally, even though the syntax allows for a SET OF AttributeValue, in an RPKI signed object, the
            // attrValues MUST consist of only a single AttributeValue.
            if (signedAttribute.getAttributeValues() == null || signedAttribute.getAttributeValues().length != 1) {
                allAttributesCorrect = false;
                break;
            }
        }

        validationResult.rejectIfFalse(allAttributesCorrect, SIGNED_ATTRS_CORRECT);

        return allAttributesCorrect;
    }

    private boolean verifySigner(SignerInformation signer, X509Certificate certificate) {
        verifySignerVersion(signer);

        validationResult.rejectIfFalse(DIGEST_ALGORITHM_OID.equals(signer.getDigestAlgOID()), CMS_SIGNER_INFO_DIGEST_ALGORITHM);
        validationResult.rejectIfFalse(ALLOWED_SIGNATURE_ALGORITHM_OIDS.contains(signer.getEncryptionAlgOID()), ENCRYPTION_ALGORITHM);
        if (!validationResult.rejectIfNull(signer.getSignedAttributes(), SIGNED_ATTRS_PRESENT)) {
            return false;
        }
        // Checks that signedAttrs match content-type and digest in EncapsulatedContentInfo are implemented in CMS
        // parsing by bouncy castle through SignerInformation.verify.
        validationResult.rejectIfNull(signer.getSignedAttributes().get(CMSAttributes.contentType), CONTENT_TYPE_ATTR_PRESENT);
        validationResult.rejectIfNull(signer.getSignedAttributes().get(CMSAttributes.messageDigest), MSG_DIGEST_ATTR_PRESENT);

        //http://tools.ietf.org/html/rfc6488#section-2.1.6.4
        //MUST include contentType and messageDigest
        //MAY include signingTime, binary-signing-time, or both
        //Other attributes MUST NOT be included

        //Check if the signedAttributes are allowed
        verifyOptionalSignedAttributes(signer);

        verifyUnsignedAttributes(signer);

        SignerId signerId = signer.getSID();
        try {
            validationResult.rejectIfFalse(signerId.match(new JcaX509CertificateHolder(certificate)), SIGNER_ID_MATCH);
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }

        return true;
    }

    /**
     * https://tools.ietf.org/html/rfc6488#section-2.1.6.1
     */
    private void verifySignerVersion(SignerInformation signer) {
        validationResult.rejectIfFalse(signer.getVersion() == CMS_OBJECT_SIGNER_VERSION, CMS_SIGNER_INFO_VERSION);
    }

    private void verifySignature(X509Certificate certificate, SignerInformation signer) {
        String errorMessage = null;
        try {
            /*
             * Use the public key for the "verifier" not the certificate, because otherwise
             * BC will reject the CMS if the signingTime is outside of the EE certificate validity
             * time. This happens occasionally and is no ground to reject according to standards:
             * http://tools.ietf.org/html/rfc6488#section-2.1.6.4.3
             */
            final SignerInformationVerifier verifier = new JcaSignerInfoVerifierBuilder(
                BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER).build(certificate.getPublicKey());

            // In addition to signature, checks:
            // * RFC 3852 11.1 Check the content-type attribute is correct
            // * RFC 6211 Validate Algorithm Identifier protection attribute if present
            // * RFC 3852 11.2 Check the message-digest attribute is correct
            // * RFC 3852 11.4 Validate countersignature attribute(s)
            validationResult.rejectIfFalse(signer.verify(verifier), SIGNATURE_VERIFICATION);
        } catch (OperatorCreationException | CMSException e) {
            errorMessage = String.valueOf(e.getMessage());
        }

        if (errorMessage != null) {
            validationResult.rejectIfFalse(false, SIGNATURE_VERIFICATION, errorMessage);
        }
    }

    /**
     * https://tools.ietf.org/html/rfc6488#section-2.1.6.7
     */
    private void verifyUnsignedAttributes(SignerInformation signer) {
        validationResult.rejectIfFalse(signer.getUnsignedAttributes() == null, UNSIGNED_ATTRS_OMITTED);
    }

    protected static BigInteger getRpkiObjectVersion(ASN1Sequence seq) {
        ASN1Primitive asn1Version = seq.getObjectAt(0).toASN1Primitive();
        BigInteger version = null;
        if (asn1Version instanceof ASN1Integer) {
            version = ((ASN1Integer) asn1Version).getValue();
        } else if (asn1Version instanceof DERTaggedObject){
            final ASN1Primitive o = ((DERTaggedObject) asn1Version).getObject();
            if (o instanceof ASN1Integer) {
                version = ((ASN1Integer) o).getValue();
            }
        }
        return version;
    }

}
