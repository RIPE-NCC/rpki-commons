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

import java.net.URI;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateValidator;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.joda.time.DateTime;

public abstract class RpkiSignedObject implements CertificateRepositoryObject {

    private static final long serialVersionUID = 1L;

    public static final String ENCRYPTION_ALGORITHM_OID = CMSSignedDataGenerator.ENCRYPTION_RSA;
    /**
     * The digestAlgorithms set MUST include only SHA-256, the OID for which is
     * 2.16.840.1.101.3.4.2.1. [RFC4055] It MUST NOT contain any other
     * algorithms.
     */
    public static final String DIGEST_ALGORITHM_OID = CMSSignedDataGenerator.DIGEST_SHA256;

    private byte[] encoded;

    private X509ResourceCertificate certificate;

    private String contentType;

    private DateTime signingTime;

    protected RpkiSignedObject(RpkiSignedObjectInfo cmsObjectData) {
        this(cmsObjectData.getEncoded(), cmsObjectData.getCertificate(), cmsObjectData.getContentType(), cmsObjectData.getSigningTime());
    }


    protected RpkiSignedObject(byte[] encoded, X509ResourceCertificate certificate, String contentType, DateTime signingTime) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;
        this.certificate = certificate;
        this.contentType = contentType;
        this.signingTime = signingTime;
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    public DateTime getSigningTime() {
        return signingTime;
    }

    public String getContentType() {
        return contentType;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }

    public boolean signedBy(X509ResourceCertificate certificate) {
        return this.certificate.equals(certificate);
    }

    public ValidityPeriod getValidityPeriod() {
        return certificate.getValidityPeriod();
    }

    public DateTime getNotValidBefore() {
        return certificate.getValidityPeriod().getNotValidBefore();
    }

    public DateTime getNotValidAfter() {
        return certificate.getValidityPeriod().getNotValidAfter();
    }

    public X500Principal getCertificateIssuer() {
        return getCertificate().getIssuer();
    }

    public X500Principal getCertificateSubject() {
        return getCertificate().getSubject();
    }

    @Override
    public URI getCrlUri() {
        return getCertificate().findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationResult result) {
        String savedCurrentLocation = result.getCurrentLocation();
        result.setLocation(getCrlUri());

        X509Crl crl = crlLocator.getCrl(getCrlUri(), context, result);

        result.setLocation(savedCurrentLocation);
        result.notNull(crl, ValidationString.OBJECTS_CRL_VALID, this);
        if (crl == null) {
            return;
        }

        X509ResourceCertificateValidator validator = new X509ResourceCertificateParentChildValidator(result, context.getCertificate(), crl, context.getResources());
        validator.validate(location, getCertificate());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getEncoded());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RpkiSignedObject other = (RpkiSignedObject) obj;
        return Arrays.equals(getEncoded(), other.getEncoded());
    }
}
