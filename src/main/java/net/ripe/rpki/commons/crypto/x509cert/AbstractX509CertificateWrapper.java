/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;

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
        return !isCa();
    }

    public boolean isCa() {
        try {
            byte[] basicConstraintsExtension = certificate.getExtensionValue(X509Extension.basicConstraints.getId());
            if (basicConstraintsExtension == null) {
                /**
                 * The Basic Constraints extension field [...] MUST be present when
                 * the Subject is a CA, and MUST NOT be present otherwise.
                 * http://tools.ietf.org/html/draft-ietf-sidr-res-certs-21#section-4.9.1
                 */
                return false;
            }
            BasicConstraints constraints = BasicConstraints.getInstance(X509ExtensionUtil.fromExtensionValue(basicConstraintsExtension));
            return constraints.isCA();
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

    public boolean isRoot() {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    public URI getManifestUri() {
        return findFirstSubjectInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST);
    }

    public URI getRepositoryUri() {
        return findFirstSubjectInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY);
    }

    public boolean isObjectIssuer() {
        return getManifestUri() != null;
    }

    public byte[] getSubjectKeyIdentifier() {
        return X509CertificateUtil.getSubjectKeyIdentifier(certificate);
    }

    public byte[] getAuthorityKeyIdentifier() {
        return X509CertificateUtil.getAuthorityKeyIdentifier(certificate);
    }

    public X500Principal getSubject() {
        return certificate.getSubjectX500Principal();
    }

    public X500Principal getIssuer() {
        return certificate.getIssuerX500Principal();
    }

    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    public ValidityPeriod getValidityPeriod() {
        return new ValidityPeriod(certificate.getNotBefore(), certificate.getNotAfter());
    }

    public BigInteger getSerialNumber() {
        return getCertificate().getSerialNumber();
    }

    public X509CertificateInformationAccessDescriptor[] getAuthorityInformationAccess() {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
            if (extensionValue == null) {
                return null;
            }
            AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getAccessDescriptions();
            return X509CertificateInformationAccessDescriptor.convertAccessDescriptors(accessDescriptions);
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

    public URI findFirstAuthorityInformationAccessByMethod(ASN1ObjectIdentifier method) {
        Validate.notNull(method, "method is null");
        return findFirstByMethod(method, "rsync", getAuthorityInformationAccess());
    }

    private URI findFirstByMethod(ASN1ObjectIdentifier method, String scheme, X509CertificateInformationAccessDescriptor[] accessDescriptor) {
        if (accessDescriptor == null) {
            return null;
        }
        for (X509CertificateInformationAccessDescriptor ad : accessDescriptor) {
            if ((method.equals(ad.getMethod())) && (ad.getLocation().getScheme().equals(scheme))) {
                return ad.getLocation();
            }
        }
        return null;
    }

    public X509CertificateInformationAccessDescriptor[] getSubjectInformationAccess() {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extension.subjectInfoAccess.getId());
            if (extensionValue == null) {
                return null;
            }
            AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getAccessDescriptions();
            return X509CertificateInformationAccessDescriptor.convertAccessDescriptors(accessDescriptions);
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

    public URI findFirstSubjectInformationAccessByMethod(ASN1ObjectIdentifier method) {
        Validate.notNull(method, "method is null");
        return findFirstByMethod(method, "rsync", getSubjectInformationAccess());
    }

    public URI[] getCrlDistributionPoints() {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extension.cRLDistributionPoints.getId());
            if (extensionValue == null) {
                return null;
            }
            CRLDistPoint crldp = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
            return convertCrlDistributionPointToUris(crldp);
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

    public URI findFirstRsyncCrlDistributionPoint() {
        URI[] crlDistributionPoints = getCrlDistributionPoints();
        if (crlDistributionPoints == null) {
            return null;
        }
        for (URI uri : crlDistributionPoints) {
            if (uri.getScheme().equals("rsync")) {
                return uri;
            }
        }
        return null;
    }

    private URI[] convertCrlDistributionPointToUris(CRLDistPoint crldp) {
        List<URI> result = new ArrayList<URI>();
        for (DistributionPoint dp : crldp.getDistributionPoints()) {
            Validate.isTrue(dp.getCRLIssuer() == null, "crlIssuer MUST be omitted");
            Validate.isTrue(dp.getReasons() == null, "reasons MUST be omitted");
            Validate.notNull(dp.getDistributionPoint(), "distributionPoint MUST be present");
            Validate.isTrue(dp.getDistributionPoint().getType() == DistributionPointName.FULL_NAME, "distributionPoint type MUST be FULL_NAME");
            GeneralNames names = (GeneralNames) dp.getDistributionPoint().getName();
            for (GeneralName name : names.getNames()) {
                Validate.isTrue(name.getTagNo() == GeneralName.uniformResourceIdentifier, "name MUST be a uniformResourceIdentifier");
                DERIA5String uri = (DERIA5String) name.getName();
                try {
                    result.add(new URI(uri.getString()));
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException(e);
                }
            }
        }
        return result.toArray(new URI[result.size()]);
    }


    public void verify(PublicKey publicKey) throws InvalidKeyException, SignatureException {
        try {
            getCertificate().verify(publicKey, DEFAULT_SIGNATURE_PROVIDER);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] getEncoded() {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

}
