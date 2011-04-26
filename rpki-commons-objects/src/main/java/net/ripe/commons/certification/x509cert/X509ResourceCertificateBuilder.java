package net.ripe.commons.certification.x509cert;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.RpkiSignedObjectEeCertificateBuilder;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.PolicyInformation;

/**
 * Generic Builder for X509ResourceCertificates<br />
 * Note that you may want to use one of the following more specific builders to build standard conform signed object EE or CA certificates:
 * @see RpkiSignedObjectEeCertificateBuilder
 * @see RpkiCaCertificateBuilder
 */
public class X509ResourceCertificateBuilder {

    private X509CertificateBuilderHelper builderHelper;
    private IpResourceSet resources;
    
    public X509ResourceCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
    }

    public X509ResourceCertificateBuilder withSignatureProvider(String signatureProvider) {
        builderHelper.withSignatureProvider(signatureProvider);
        return this;
    }

    public X509ResourceCertificateBuilder withSerial(BigInteger serial) {
        builderHelper.withSerial(serial);
        return this;
    }

    public X509ResourceCertificateBuilder withSubjectDN(X500Principal subjectDN) {
        builderHelper.withSubjectDN(subjectDN);
        return this;
    }

    public X509ResourceCertificateBuilder withIssuerDN(X500Principal issuerDN) {
        builderHelper.withIssuerDN(issuerDN);
        return this;
    }

    public X509ResourceCertificateBuilder withValidityPeriod(ValidityPeriod validityPeriod) {
        builderHelper.withValidityPeriod(validityPeriod);
        return this;
    }

    public X509ResourceCertificateBuilder withPublicKey(PublicKey publicKey) {
        builderHelper.withPublicKey(publicKey);
        return this;
    }

    public X509ResourceCertificateBuilder withSigningKeyPair(KeyPair signingKey) {
        builderHelper.withSigningKeyPair(signingKey);
        return this;
    }

    public X509ResourceCertificateBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        builderHelper.withSignatureAlgorithm(signatureAlgorithm);
        return this;
    }

    public X509ResourceCertificateBuilder withKeyUsage(int keyUsage) {
        builderHelper.withKeyUsage(keyUsage);
        return this;
    }

    public X509ResourceCertificateBuilder withResources(IpResourceSet resources) {
        this.resources = resources;
        builderHelper.withResources(resources);
        return this;
    }

    public X509ResourceCertificateBuilder withCa(boolean ca) {
        builderHelper.withCa(ca);
        return this;
    }

    public X509ResourceCertificateBuilder withSubjectKeyIdentifier(boolean add) {
        builderHelper.withSubjectKeyIdentifier(add);
        return this;
    }

    public X509ResourceCertificateBuilder withAuthorityKeyIdentifier(boolean add) {
        builderHelper.withAuthorityKeyIdentifier(add);
        return this;
    }

    public X509ResourceCertificateBuilder withCrlDistributionPoints(URI... uris) {
        builderHelper.withCrlDistributionPoints(uris);
        return this;
    }

    public X509ResourceCertificateBuilder withAuthorityInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        builderHelper.withAuthorityInformationAccess(descriptors);
        return this;
    }

    public X509ResourceCertificateBuilder withSubjectInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        builderHelper.withSubjectInformationAccess(descriptors);
        return this;
    }

    public X509ResourceCertificateBuilder withPolicies(PolicyInformation... policies) {
        builderHelper.withPolicies(policies);
        return this;
    }

    public X509ResourceCertificate build() {
        Validate.notNull(resources, "no resources");
        Validate.isTrue(!resources.isEmpty(), "empty resources");
        return new X509ResourceCertificate(builderHelper.generateCertificate());
    }


}