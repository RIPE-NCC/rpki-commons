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
package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;

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
import org.joda.time.DateTimeZone;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import static net.ripe.rpki.commons.crypto.cms.RpkiSignedObject.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public abstract class RpkiSignedObjectParser {

    private byte[] encoded;

    private X509ResourceCertificate certificate;

    protected ASN1ObjectIdentifier contentType;

    private DateTime signingTime;

    private ValidationResult validationResult;

    public final void parse(String location, byte[] encoded) { // NOPMD - ArrayIsStoredDirectly
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
        } catch (CMSException e) {
            validationResult.rejectIfFalse(false, CMS_DATA_PARSING);
            return;
        }
        validationResult.rejectIfFalse(true, CMS_DATA_PARSING);

        if (!validationResult.hasFailures()) {
            parseContent(sp);
        }
        if (!validationResult.hasFailures()) {
            parseCmsCertificate(sp);
        }
        if (!validationResult.hasFailures()) {
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

        if (!verifyAndStoreSigningTime(signer)) {
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
        } catch (CMSException e) {
            return null; // Caller will validate that the SignerInformationStore is not null
        } catch (RuntimeException e) {
            return null; // Caller will validate that the SignerInformationStore is not null
        }
    }
    
    private boolean isAllowedSignedAttribute(Attribute signedAttribute) {
    	
    	//This isn't in the bouncy castle file CMSAttributes, where the other CMS OID come from.
    	ASN1ObjectIdentifier binarySigningTimeOID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.46");
    	ASN1ObjectIdentifier attributeOID = signedAttribute.getAttrType();
    	
    	//Check if the attribute is any of the allowed ones.
    	return binarySigningTimeOID.equals(attributeOID)
                || CMSAttributes.signingTime.equals(attributeOID)
                || CMSAttributes.contentType.equals(attributeOID)
    			|| CMSAttributes.messageDigest.equals(attributeOID);
    }
    
    private boolean verifyOptionalSignedAttributes(SignerInformation signer) {

    	//To loop over
    	ASN1EncodableVector signedAttributes = signer.getSignedAttributes().toASN1EncodableVector();
    	
        boolean allAttributesCorrect = true;
        for(int i = 0; i < signedAttributes.size(); i++){
        	ASN1Encodable signedAttribute = signedAttributes.get(i);
        	if(!isAllowedSignedAttribute((Attribute)signedAttribute)){
        		allAttributesCorrect = false;
        		break;
        	}
        }
        
        if(allAttributesCorrect){
        	validationResult.pass(SIGNED_ATTRS_CORRECT);
        } else {
    		validationResult.warn(SIGNED_ATTRS_CORRECT);
        }
        
        return allAttributesCorrect;
    }

    private boolean verifySigner(SignerInformation signer, X509Certificate certificate) {
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
        
        SignerId signerId = signer.getSID();
        try {
            validationResult.rejectIfFalse(signerId.match(new JcaX509CertificateHolder(certificate)), SIGNER_ID_MATCH);
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }

        return true;
    }

    private boolean verifyAndStoreSigningTime(SignerInformation signer) {
        Attribute signingTimeAttibute = signer.getSignedAttributes().get(CMSAttributes.signingTime);
        if (!validationResult.rejectIfNull(signingTimeAttibute, SIGNING_TIME_ATTR_PRESENT)) {
            return false;
        }
        if (!validationResult.rejectIfFalse(signingTimeAttibute.getAttrValues().size() == 1, ONLY_ONE_SIGNING_TIME_ATTR)) {
            return false;
        }

        Time signingTimeDate = Time.getInstance(signingTimeAttibute.getAttrValues().getObjectAt(0));
        signingTime = new DateTime(signingTimeDate.getDate().getTime(), DateTimeZone.UTC);
        return true;
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
            validationResult.rejectIfFalse(signer.verify(new JcaSignerInfoVerifierBuilder(BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER).build(certificate.getPublicKey())), SIGNATURE_VERIFICATION);
        } catch (OperatorCreationException e) {
            errorMessage = String.valueOf(e.getMessage());
        } catch (CMSException e) {
            errorMessage = String.valueOf(e.getMessage());
        }

        if (errorMessage != null) {
            validationResult.rejectIfFalse(false, SIGNATURE_VERIFICATION, errorMessage);
        }
    }

}
