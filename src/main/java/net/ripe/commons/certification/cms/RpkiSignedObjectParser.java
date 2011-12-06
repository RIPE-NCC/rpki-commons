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
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;


public abstract class RpkiSignedObjectParser {

    private byte[] encoded;

    private X509ResourceCertificate certificate;

    private ASN1ObjectIdentifier contentType;

    private DateTime signingTime;

    private ValidationResult validationResult;

    private String location;

    protected RpkiSignedObjectParser() {
        validationResult = new ValidationResult();
    }

    protected RpkiSignedObjectParser(ValidationResult result) {
        this.validationResult = result;
    }

    public void parse(String location, byte[] encoded) { // NOPMD - ArrayIsStoredDirectly
        this.location = location;
        this.encoded = encoded;
        validationResult.setLocation(new ValidationLocation(location));
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

    public abstract void decodeContent(DEREncodable encoded);

    private void parseCms() {
        CMSSignedDataParser sp = null;
        try {
            sp = new CMSSignedDataParser(encoded);
        } catch (CMSException e) {
            validationResult.isTrue(false, CMS_DATA_PARSING);
            return;
        }
        validationResult.isTrue(true, CMS_DATA_PARSING);

        if (!validationResult.hasFailures()) { parseContent(sp); }
        if (!validationResult.hasFailures()) { parseCmsCertificate(sp); }
        if (!validationResult.hasFailures()) { verifyCmsSigning(sp, certificate.getCertificate()); }
    }

    private void parseContent(CMSSignedDataParser sp) {
        contentType = sp.getSignedContent().getContentType();

        InputStream signedContentStream = sp.getSignedContent().getContentStream();
        ASN1InputStream asn1InputStream = new ASN1InputStream(signedContentStream);

        try {
            decodeContent(asn1InputStream.readObject());
        } catch (IOException e) {
            validationResult.isTrue(false, DECODE_CONTENT);
            return;
        }
        validationResult.isTrue(true, DECODE_CONTENT);

        try {
            validationResult.isTrue(asn1InputStream.readObject() == null, ONLY_ONE_SIGNED_OBJECT);
            asn1InputStream.close();
        } catch (IOException e) {
            validationResult.isTrue(false, CMS_CONTENT_PARSING);
        }
        validationResult.isTrue(true, CMS_CONTENT_PARSING);
    }

    private void parseCmsCertificate(CMSSignedDataParser sp) {
        Collection<? extends Certificate> certificates = extractCertificate(sp);

        if (!validationResult.notNull(certificates, GET_CERTS_AND_CRLS)) {
            return;
        }
        if (!validationResult.isTrue(certificates.size() == 1, ONLY_ONE_EE_CERT_ALLOWED)) {
            return;
        }
        if (!validationResult.isTrue(certificates.iterator().next() instanceof X509Certificate, CERT_IS_X509CERT)) {
            return;
        }

        certificate = parseCertificate(certificates);

        validationResult.isTrue(certificate.isEe(), CERT_IS_EE_CERT);
        validationResult.notNull(certificate.getSubjectKeyIdentifier(), CERT_HAS_SKI);
    }

    private X509ResourceCertificate parseCertificate(Collection<? extends Certificate> certificates) {
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        try {
            X509Certificate x509certificate = (X509Certificate) certificates.iterator().next();
            parser.parse(location, x509certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
        return parser.getCertificate();
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
        if (!validationResult.notNull(signerStore, GET_SIGNER_INFO)) {
            return null;
        }

        Collection<?> signers = signerStore.getSigners();
        validationResult.isTrue(signers.size() == 1, ONLY_ONE_SIGNER);

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
        validationResult.isTrue(DIGEST_ALGORITHM_OID.equals(signer.getDigestAlgOID()), CMS_SIGNER_INFO_DIGEST_ALGORITHM);
        validationResult.isTrue(ENCRYPTION_ALGORITHM_OID.equals(signer.getEncryptionAlgOID()), ENCRYPTION_ALGORITHM);
        if (!validationResult.notNull(signer.getSignedAttributes(), SIGNED_ATTRS_PRESENT)) {
            return false;
        }
        validationResult.notNull(signer.getSignedAttributes().get(CMSAttributes.contentType), CONTENT_TYPE_ATTR_PRESENT);
        validationResult.notNull(signer.getSignedAttributes().get(CMSAttributes.messageDigest), MSG_DIGEST_ATTR_PRESENT);
        SignerId signerId = signer.getSID();
        validationResult.isTrue(signerId.match(certificate), SIGNER_ID_MATCH);

        return true;
    }

    private boolean verifyAndStoreSigningTime(SignerInformation signer) {
        Attribute signingTimeAttibute = signer.getSignedAttributes().get(CMSAttributes.signingTime);
        if (!validationResult.notNull(signingTimeAttibute, SIGNING_TIME_ATTR_PRESENT)) {
            return false;
        }
        if (!validationResult.isTrue(signingTimeAttibute.getAttrValues().size() == 1, ONLY_ONE_SIGNING_TIME_ATTR)) {
            return false;
        }

        Time signingTimeDate = Time.getInstance(signingTimeAttibute.getAttrValues().getObjectAt(0));
        signingTime = new DateTime(signingTimeDate.getDate().getTime(), DateTimeZone.UTC);
        return true;
    }

    private void verifySignature(X509Certificate certificate, SignerInformation signer) {
        boolean errorOccured = false;
        try {
            validationResult.isTrue(signer.verify(certificate.getPublicKey(), (String) null), SIGNATURE_VERIFICATION);
        } catch (NoSuchAlgorithmException e) {
            errorOccured = true;
        } catch (NoSuchProviderException e) {
            errorOccured = true;
        } catch (CMSException e) {
            errorOccured = true;
        }

        if (errorOccured) {
            validationResult.isTrue(false, SIGNATURE_VERIFICATION);
        }
    }
}
