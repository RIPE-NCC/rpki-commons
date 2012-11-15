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
package net.ripe.commons.certification.cms;

import static net.ripe.commons.certification.cms.RpkiSignedObject.*;
import static net.ripe.commons.certification.validation.ValidationString.*;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import net.ripe.commons.certification.BouncyCastleUtil;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.StoreException;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public abstract class RpkiSignedObjectParser {

    private byte[] encoded;

    private X509ResourceCertificate certificate;

    private ASN1ObjectIdentifier contentType;

    private DateTime signingTime;

    private ValidationResult validationResult;

    protected RpkiSignedObjectParser() {
        validationResult = new ValidationResult();
    }

    protected RpkiSignedObjectParser(ValidationResult result) {
        this.validationResult = result;
    }

    public final void parse(String location, byte[] encoded) { // NOPMD - ArrayIsStoredDirectly
        parse(new ValidationLocation(location), encoded);
    }

    public void parse(ValidationLocation location, byte[] encoded) {
        this.encoded = encoded;
        validationResult.setLocation(location);
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

    public abstract void decodeContent(ASN1Encodable encoded);

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

    private void parseContent(CMSSignedDataParser sp) {
        contentType = sp.getSignedContent().getContentType();

        InputStream signedContentStream = sp.getSignedContent().getContentStream();
        ASN1InputStream asn1InputStream = new ASN1InputStream(signedContentStream);

        try {
            decodeContent(asn1InputStream.readObject());
        } catch (IOException e) {
            validationResult.rejectIfFalse(false, DECODE_CONTENT);
            return;
        }
        validationResult.rejectIfFalse(true, DECODE_CONTENT);

        try {
            validationResult.rejectIfFalse(asn1InputStream.readObject() == null, ONLY_ONE_SIGNED_OBJECT);
            asn1InputStream.close();
        } catch (IOException e) {
            validationResult.rejectIfFalse(false, CMS_CONTENT_PARSING);
        }
        validationResult.rejectIfFalse(true, CMS_CONTENT_PARSING);
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
            X509ResourceCertificateParser parser = new X509ResourceCertificateParser(validationResult);
            parser.parse(validationResult.getCurrentLocation(), x509certificate.getEncoded());
            return parser.isSuccess() ? parser.getCertificate() : null;
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException("cannot parse already decoded X509 certificate: " + e, e);
        }
    }

    private Collection<? extends Certificate> extractCertificate(CMSSignedDataParser sp) {
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
        validationResult.rejectIfFalse(signers.size() == 1, ONLY_ONE_SIGNER);

        return (SignerInformation) signers.iterator().next();
    }

    private SignerInformationStore getSignerStore(CMSSignedDataParser sp) {
        try {
            return sp.getSignerInfos();
        } catch (CMSException e) {
            return null; // Caller will validate that the SignerInformationStore is not null
        }
    }

    private boolean verifySigner(SignerInformation signer, X509Certificate certificate) {
        validationResult.rejectIfFalse(DIGEST_ALGORITHM_OID.equals(signer.getDigestAlgOID()), CMS_SIGNER_INFO_DIGEST_ALGORITHM);
        validationResult.rejectIfFalse(ENCRYPTION_ALGORITHM_OID.equals(signer.getEncryptionAlgOID()), ENCRYPTION_ALGORITHM);
        if (!validationResult.rejectIfNull(signer.getSignedAttributes(), SIGNED_ATTRS_PRESENT)) {
            return false;
        }
        validationResult.rejectIfNull(signer.getSignedAttributes().get(CMSAttributes.contentType), CONTENT_TYPE_ATTR_PRESENT);
        validationResult.rejectIfNull(signer.getSignedAttributes().get(CMSAttributes.messageDigest), MSG_DIGEST_ATTR_PRESENT);
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
