/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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

import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationResult;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.StoreException;
import org.joda.time.DateTime;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.ALLOWED_SIGNATURE_ALGORITHM_OIDS;
import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.DIGEST_ALGORITHM_OID;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public abstract class RpkiSignedObjectParser {

    // binary-signing-time is not yet in BC CMSAttributes; define it here until
    // https://github.com/bcgit/bc-java/pull/932 is merged.
    public static final ASN1ObjectIdentifier BINARY_SIGNING_TIME_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.46");

    private static final int CMS_OBJECT_VERSION = 3;
    private static final int CMS_OBJECT_SIGNER_VERSION = 3;

    private byte[] encoded;

    private X509ResourceCertificate certificate;

    protected ASN1ObjectIdentifier contentType;

    private DateTime signingTime;

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

    protected DateTime getSigningTime() {
        return signingTime;
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
            return;
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

        validationResult.rejectIfFalse(crls.size() == 0, CMS_NO_CRL_ALLOWED);
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

        if (!extractSigningTime(signer)) {
            return;
        }

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
        return BINARY_SIGNING_TIME_OID.equals(attributeOID)
                || CMSAttributes.signingTime.equals(attributeOID)
                || CMSAttributes.contentType.equals(attributeOID)
                        || CMSAttributes.messageDigest.equals(attributeOID);
    }

    private boolean verifyOptionalSignedAttributes(SignerInformation signer) {

        //To loop over
        ASN1EncodableVector signedAttributes = signer.getSignedAttributes().toASN1EncodableVector();

        boolean allAttributesCorrect = true;
        for (int i = 0; i < signedAttributes.size(); i++) {
            ASN1Encodable signedAttribute = signedAttributes.get(i);
            if (!isAllowedSignedAttribute((Attribute) signedAttribute)) {
                allAttributesCorrect = false;
                break;
            }
        }

        if (allAttributesCorrect) {
            validationResult.pass(SIGNED_ATTRS_CORRECT);
        } else {
            validationResult.warn(SIGNED_ATTRS_CORRECT);
        }

        return allAttributesCorrect;
    }

    private boolean verifySigner(SignerInformation signer, X509Certificate certificate) {
        verifySignerVersion(signer);
        validationResult.rejectIfFalse(DIGEST_ALGORITHM_OID.equals(signer.getDigestAlgOID()), CMS_SIGNER_INFO_DIGEST_ALGORITHM);
        validationResult.rejectIfFalse(ALLOWED_SIGNATURE_ALGORITHM_OIDS.contains(signer.getEncryptionAlgOID()), ENCRYPTION_ALGORITHM);
        if (!validationResult.rejectIfNull(signer.getSignedAttributes(), SIGNED_ATTRS_PRESENT)) {
            return false;
        }
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

    /**
     * Extract signing time from the signer information.
     *
     * Signing time is either provided in the signing-time [RFC5652] or binary-signing-time [RFC6019]
     * attribute, or neither. As stated in RFC 6019 Section 4 [Security Considerations] "only one
     * of these attributes SHOULD be present". [..] "However, if both of these attributes are present,
     * they MUST provide the same date and time."
     */
    private boolean extractSigningTime(SignerInformation signer) {
        ImmutablePair<DateTime, Boolean> signingTime = extractTime(CMSAttributes.signingTime, ONLY_ONE_SIGNING_TIME_ATTR, signer);
        ImmutablePair<DateTime, Boolean> binarySigningTime = extractTime(BINARY_SIGNING_TIME_OID, ONLY_ONE_BINARY_SIGNING_TIME_ATTR, signer);
        boolean valid = signingTime.right && binarySigningTime.right;

        if (signingTime.left != null && binarySigningTime.left != null) {
            valid = validationResult.rejectIfFalse(signingTime.left.equals(binarySigningTime.left), SIGNING_TIME_MUST_EQUAL_BINARY_SIGNING_TIME) && valid;
        }

        if (valid) {
            this.signingTime = signingTime.left != null ? signingTime.left : binarySigningTime.left;
        }
        return valid;
    }

    private ImmutablePair<DateTime, Boolean> extractTime(ASN1ObjectIdentifier identifier, String onlyOneValidationKey, SignerInformation signer) {
        Attribute attr = signer.getSignedAttributes().get(identifier);
        if (attr == null) {
            return ImmutablePair.of(null, true);
        }
        if (!validationResult.rejectIfFalse(attr.getAttrValues().size() == 1, onlyOneValidationKey)) {
            return ImmutablePair.of(null, false);
        }
        DateTime value = UTC.dateTime(Time.getInstance(attr.getAttrValues().getObjectAt(0)).getDate().getTime());
        return ImmutablePair.of(value, true);
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
