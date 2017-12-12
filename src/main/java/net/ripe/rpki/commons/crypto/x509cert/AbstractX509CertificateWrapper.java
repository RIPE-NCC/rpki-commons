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
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public abstract class AbstractX509CertificateWrapper implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final ASN1ObjectIdentifier POLICY_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.14.2");

    public static final PolicyInformation POLICY_INFORMATION = new PolicyInformation(POLICY_OID);

    private final X509Certificate certificate;


    protected AbstractX509CertificateWrapper(X509Certificate certificate) {
        Validate.notNull(certificate);
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public byte[] getEncoded() {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

    public ASN1ObjectIdentifier getCertificatePolicy() {
        return POLICY_OID;
    }

    @Override
    public int hashCode() {
        return certificate.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AbstractX509CertificateWrapper)) {
            return false;
        }
        final AbstractX509CertificateWrapper other = (AbstractX509CertificateWrapper) obj;
        return certificate.equals(other.certificate);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("serial", getSerialNumber()).append("subject", getSubject()).toString();
    }

    public boolean isEe() {
        return X509CertificateUtil.isEe(certificate);
    }

    public boolean isCa() {
        return X509CertificateUtil.isCa(certificate);
    }

    public boolean isRoot() {
        return X509CertificateUtil.isRoot(certificate);
    }

    public boolean isRouter() {
        return X509CertificateUtil.isRouter(certificate);
    }

    public URI getManifestUri() {
        return X509CertificateUtil.getManifestUri(certificate);
    }

    public URI getRepositoryUri() {
        return X509CertificateUtil.getRepositoryUri(certificate);
    }

    public URI getRrdpNotifyUri() {
        return X509CertificateUtil.getRrdpNotifyUri(certificate);
    }

    public boolean isObjectIssuer() {
        return X509CertificateUtil.isObjectIssuer(certificate);
    }

    public byte[] getSubjectKeyIdentifier() {
        return X509CertificateUtil.getSubjectKeyIdentifier(certificate);
    }

    public byte[] getAuthorityKeyIdentifier() {
        return X509CertificateUtil.getAuthorityKeyIdentifier(certificate);
    }

    public X500Principal getSubject() {
        return X509CertificateUtil.getSubject(certificate);
    }

    public X500Principal getIssuer() {
        return X509CertificateUtil.getIssuer(certificate);
    }

    public PublicKey getPublicKey() {
        return X509CertificateUtil.getPublicKey(certificate);
    }

    public ValidityPeriod getValidityPeriod() {
        return X509CertificateUtil.getValidityPeriod(certificate);
    }

    public BigInteger getSerialNumber() {
        return X509CertificateUtil.getSerialNumber(certificate);
    }

    public X509CertificateInformationAccessDescriptor[] getAuthorityInformationAccess() {
        return X509CertificateUtil.getAuthorityInformationAccess(certificate);
    }

    public URI findFirstAuthorityInformationAccessByMethod(ASN1ObjectIdentifier method) {
        return X509CertificateUtil.findFirstAuthorityInformationAccessByMethod(certificate, method);
    }

    public X509CertificateInformationAccessDescriptor[] getSubjectInformationAccess() {
        return X509CertificateUtil.getSubjectInformationAccess(certificate);
    }

    public URI findFirstSubjectInformationAccessByMethod(ASN1ObjectIdentifier method) {
        return X509CertificateUtil.findFirstSubjectInformationAccessByMethod(certificate, method);
    }

    public URI[] getCrlDistributionPoints() {
        return X509CertificateUtil.getCrlDistributionPoints(certificate);
    }

    public URI findFirstRsyncCrlDistributionPoint() {
        return X509CertificateUtil.findFirstRsyncCrlDistributionPoint(certificate);
    }

    public void verify(PublicKey publicKey) throws InvalidKeyException, SignatureException {
        X509CertificateUtil.verify(certificate, publicKey);
    }

    protected boolean hasErrorInRevocationCheck(List<ValidationCheck> failures) {
        for (ValidationCheck validationCheck : failures) {
            if (ValidationString.CERT_NOT_REVOKED.equals(validationCheck.getKey()) && validationCheck.getStatus() == ValidationStatus.ERROR) {
                return true;
            }
        }
        return false;
    }
}
