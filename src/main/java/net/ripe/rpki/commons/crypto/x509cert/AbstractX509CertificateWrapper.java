package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
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
import java.util.Base64;
import java.util.List;

public abstract class AbstractX509CertificateWrapper implements Serializable {

    private static final long serialVersionUID = 1L;

    // https://tools.ietf.org/html/rfc6484#section-1.2
    //    id-cp-ipAddr-asNumber OBJECT IDENTIFIER ::= { iso(1)
    //                         identified-organization(3) dod(6) internet(1)
    //                         security(5) mechanisms(5) pkix(7) cp(14) 2 }
    public static final ASN1ObjectIdentifier POLICY_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.14.2");

    public static final PolicyInformation POLICY_INFORMATION = new PolicyInformation(POLICY_OID);

    private final X509Certificate certificate;

    private final boolean ca;

    protected AbstractX509CertificateWrapper(X509Certificate certificate) {
        Validate.notNull(certificate);
        this.certificate = certificate;
        this.ca = X509CertificateUtil.isCa(certificate);
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

    public String getBase64String() {
        return Base64.getEncoder().encodeToString(this.getEncoded());
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
        return ca;
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
