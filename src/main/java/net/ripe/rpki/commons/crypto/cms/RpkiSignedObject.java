package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.*;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

public class RpkiSignedObject implements CertificateRepositoryObject {

    /**
     * CMS signed objects must indicate signing algorithm as "sha256WithRsa".
     */
    public static final String SHA256WITHRSA_ENCRYPTION_OID = PKCSObjectIdentifiers.sha256WithRSAEncryption.getId();

    /**
     * However, older versions of BouncyCastle did not support this OID and use "rsaEncryption" instead.
     * We accept both when parsing and validating, but sign with "sha256WithRsa" now.
     */
    public static final String RSA_ENCRYPTION_OID = CMSSignedGenerator.ENCRYPTION_RSA;

    public static final List<String> ALLOWED_SIGNATURE_ALGORITHM_OIDS = Arrays.asList(
        SHA256WITHRSA_ENCRYPTION_OID,
        RSA_ENCRYPTION_OID
    );

    /**
     * The digestAlgorithms set MUST include only SHA-256, the OID for which is
     * 2.16.840.1.101.3.4.2.1. [RFC4055] It MUST NOT contain any other
     * algorithms.
     */
    public static final String DIGEST_ALGORITHM_OID = CMSSignedGenerator.DIGEST_SHA256;

    private final byte[] encoded;

    private final X509ResourceCertificate certificate;

    private final String oid; // Storing oid as String  so that this class is serializable

    private final @Nullable Instant signingTime;

    private Boolean revoked;

    protected RpkiSignedObject(RpkiSignedObjectInfo cmsObjectData) {
        this(cmsObjectData.getEncoded(), cmsObjectData.getCertificate(), cmsObjectData.getContentType(), cmsObjectData.getSigningTime());
    }

    protected RpkiSignedObject(byte[] encoded, X509ResourceCertificate certificate, ASN1ObjectIdentifier oid, @Nullable Instant signingTime) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;
        this.certificate = certificate;
        this.oid = oid.getId();
        this.signingTime = signingTime;
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    public @Nullable Instant getSigningTime() {
        return signingTime;
    }

    public ASN1ObjectIdentifier getContentType() {
        return new ASN1ObjectIdentifier(oid);
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

    public @NotNull Instant getNotValidBefore() {
        return certificate.getValidityPeriod().notValidBefore();
    }

    public @NotNull Instant getNotValidAfter() {
        return certificate.getValidityPeriod().notValidAfter();
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
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        ValidationLocation savedCurrentLocation = result.getCurrentLocation();
        result.setLocation(new ValidationLocation(getCrlUri()));

        X509Crl crl = crlLocator.getCrl(getCrlUri(), context, result);

        result.setLocation(savedCurrentLocation);
        result.rejectIfNull(crl, ValidationString.OBJECTS_CRL_VALID, getCrlUri().toString());
        if (crl != null) {
            validateWithCrl(location, context, options, result, crl);
        }

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, X509Crl crl, URI crlUri, ValidationOptions options, ValidationResult result) {
        result.rejectIfNull(crl, ValidationString.OBJECTS_CRL_VALID, crlUri.toString());
        if (crl != null) {
            validateWithCrl(location, context, options, result, crl);
        }

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));
    }

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }

    protected void validateWithCrl(String location, CertificateRepositoryObjectValidationContext context, ValidationOptions options, ValidationResult result, X509Crl crl) {
        X509ResourceCertificateParentChildValidator validator = ResourceValidatorFactory.getX509ResourceCertificateStrictValidator(context, options, result, crl);
        validator.validate(location, getCertificate());
    }

    private boolean hasErrorInRevocationCheck(List<ValidationCheck> failures) {
        for (ValidationCheck validationCheck : failures) {
            if (ValidationString.CERT_NOT_REVOKED.equals(validationCheck.getKey()) && validationCheck.getStatus() == ValidationStatus.ERROR) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isPastValidityTime(@NotNull Instant instant) {
        return getCertificate().isPastValidityTime(instant);
    }

    @Override
    public boolean isRevoked() {
        if (revoked == null) {
            throw new IllegalStateException("isRevoked() could only be called after validate()");
        }
        return revoked;
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
