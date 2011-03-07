package net.ripe.commons.certification.x509cert;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateValidator;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static net.ripe.commons.certification.x509cert.X509CertificateBuilder.DEFAULT_SIGNATURE_PROVIDER;

public class X509PlainCertificate implements CertificateRepositoryObject {

    private static final long serialVersionUID = 1L;

    public static final DERObjectIdentifier POLICY_OID = new DERObjectIdentifier("1.3.6.1.5.5.7.14.2");

    public static final PolicyInformation POLICY_INFORMATION = new PolicyInformation(POLICY_OID);

    private final X509Certificate certificate;

    protected X509PlainCertificate(X509Certificate certificate) {
        Validate.notNull(certificate);
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public DERObjectIdentifier getCertificatePolicy() {
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
        if (!(obj instanceof X509PlainCertificate)) {
            return false;
        }
        final X509PlainCertificate other = (X509PlainCertificate) obj;
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
            byte[] basicConstraintsExtension = certificate.getExtensionValue(X509Extensions.BasicConstraints.getId());
            if (basicConstraintsExtension == null) {
                return false;
            }
            BasicConstraints constraints = BasicConstraints.getInstance(X509ExtensionUtil.fromExtensionValue(basicConstraintsExtension));
            return constraints.isCA();
        } catch (IOException e) {
            throw new X509PlainCertificateException(e);
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

    @Override
    public byte[] getEncoded() {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new X509PlainCertificateException(e);
        }
    }

    @Override
    public URI getCrlUri() {
        return findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public URI getParentCertificateUri() {
        return findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS);
    }

    public X509CertificateInformationAccessDescriptor[] getAuthorityInformationAccess() {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
            if (extensionValue == null) {
                return null;
            }
            AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getAccessDescriptions();
            return X509CertificateInformationAccessDescriptor.convertAccessDescriptors(accessDescriptions);
        } catch (IOException e) {
            throw new X509PlainCertificateException(e);
        }
    }

    public URI findFirstAuthorityInformationAccessByMethod(DERObjectIdentifier method) {
        Validate.notNull(method, "method is null");
        return findFirstByMethod(method, "rsync", getAuthorityInformationAccess());
    }

    private URI findFirstByMethod(DERObjectIdentifier method, String scheme, X509CertificateInformationAccessDescriptor[] accessDescriptor) {
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
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.SubjectInfoAccess.getId());
            if (extensionValue == null) {
                return null;
            }
            AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getAccessDescriptions();
            return X509CertificateInformationAccessDescriptor.convertAccessDescriptors(accessDescriptions);
        } catch (IOException e) {
            throw new X509PlainCertificateException(e);
        }
    }

    public URI findFirstSubjectInformationAccessByMethod(DERObjectIdentifier method) {
        Validate.notNull(method, "method is null");
        return findFirstByMethod(method, "rsync", getSubjectInformationAccess());
    }

    public URI[] getCrlDistributionPoints() {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
            if (extensionValue == null) {
                return null;
            }
            CRLDistPoint crldp = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
            return convertCrlDistributionPointToUris(crldp);
        } catch (IOException e) {
            throw new X509PlainCertificateException(e);
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

    @Override
    public void validate(String location, X509ResourceCertificateValidator validator) {
        X509CertificateParser<X509ResourceCertificate> parser = X509CertificateParser.forResourceCertificate(validator.getValidationResult());
        parser.parse(location, getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        validator.validate(location, this);
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationResult result) {
        X509Crl crl = null;
        if (!isRoot()) {
            String savedCurrentLocation = result.getCurrentLocation();
            result.push(getCrlUri());
            crl = crlLocator.getCrl(getCrlUri(), context, result);
            result.push(savedCurrentLocation);
            result.notNull(crl, ValidationString.OBJECTS_CRL_VALID, this);
            if (crl == null) {
                return;
            }
        }
        X509ResourceCertificateValidator validator = new X509ResourceCertificateParentChildValidator(result, context.getCertificate(), crl, context.getResources());
        validator.validate(location, this);
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

}
