package net.ripe.commons.provisioning.x509;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper;
import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.joda.time.DateTime;


public class ProvisioningIdentityCertificateBuilder {

    private static final int DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW = 10;

    private X509CertificateBuilderHelper builderHelper;

    private KeyPair selfSigningKeyPair;

    private X500Principal selfSigningSubject;

    private URI crlRsyncUri;

    private URI repositoryRsyncUri;


    public ProvisioningIdentityCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
    }

    public ProvisioningIdentityCertificateBuilder withSelfSigningKeyPair(KeyPair selfSigningKeyPair) {
        this.selfSigningKeyPair = selfSigningKeyPair;
        builderHelper.withPublicKey(selfSigningKeyPair.getPublic());
        builderHelper.withSigningKeyPair(selfSigningKeyPair);
        return this;
    }

    public ProvisioningIdentityCertificateBuilder withSelfSigningSubject(X500Principal selfSigningSubject) {
        this.selfSigningSubject = selfSigningSubject;
        builderHelper.withSubjectDN(selfSigningSubject);
        builderHelper.withIssuerDN(selfSigningSubject);
        return this;
    }

    public ProvisioningIdentityCertificateBuilder withCrlRsyncUri(URI crlRsyncUri) {
        this.crlRsyncUri = crlRsyncUri;
        builderHelper.withCrlDistributionPoints(crlRsyncUri);
        return this;
    }

    public ProvisioningIdentityCertificateBuilder withRepositoryRsyncUri(URI repositoryRsyncUri) {
        this.repositoryRsyncUri = repositoryRsyncUri;
        DERObjectIdentifier caCertRepoIdentifier = X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
        X509CertificateInformationAccessDescriptor descriptor = new X509CertificateInformationAccessDescriptor(caCertRepoIdentifier, repositoryRsyncUri);
        builderHelper.withSubjectInformationAccess(descriptor);
        return this;
    }

    public ProvisioningIdentityCertificate build() {
        Validate.notNull(selfSigningKeyPair, "Self Signing KeyPair is required");
        Validate.notNull(selfSigningSubject, "Self Signing DN is required");
        Validate.notNull(crlRsyncUri, "CRL URI is required");
        Validate.notNull(repositoryRsyncUri, "SIA ca repository is required");
        setUpImplicitRequirementsForBuilderHelper();
        return new ProvisioningIdentityCertificate(builderHelper.generateCertificate());
    }

    private void setUpImplicitRequirementsForBuilderHelper() {
        builderHelper.withSerial(BigInteger.ONE); // Self-signed! So this is the first!
        builderHelper.withValidityPeriod(new ValidityPeriod(new DateTime(), new DateTime().plusYears(DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW)));
        builderHelper.withCa(true);
    }
}
