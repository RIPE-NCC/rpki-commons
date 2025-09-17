package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.apache.commons.lang3.Validate;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.EnumSet;

/**
 * Generic Builder for X509ResourceCertificates.
 * Note that you may want to use one of the following more specific builders to build standard conform signed object EE or CA certificates:
 *
 * @see RpkiSignedObjectEeCertificateBuilder
 * @see RpkiCaCertificateBuilder
 */
public class X509ResourceCertificateBuilder {
    private final X509CertificateBuilderHelper builderHelper;
    private IpResourceSet resources = new IpResourceSet();
    private EnumSet<IpResourceType> inheritedResourceTypes = EnumSet.noneOf(IpResourceType.class);

    public X509ResourceCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
        builderHelper.withResources(resources);
        // https://tools.ietf.org/html/rfc6487#section-4.8.9
        builderHelper.withPolicies(AbstractX509CertificateWrapper.POLICY_INFORMATION);
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

    public X509ResourceCertificateBuilder withRouter(boolean isRouter) {
        builderHelper.withRouter(isRouter);
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

    public X509ResourceCertificate build() {
        if (inheritedResourceTypes.isEmpty()) {
            Validate.notNull(resources, "no resources");
            Validate.isTrue(!resources.isEmpty(), "empty resources");
        }
        return new X509ResourceCertificate(builderHelper.generateCertificate());
    }

    @SuppressWarnings("java:S1319")
    public X509ResourceCertificateBuilder withInheritedResourceTypes(EnumSet<IpResourceType> resourceTypes) {
        this.inheritedResourceTypes = resourceTypes;
        builderHelper.withInheritedResourceTypes(resourceTypes);
        return this;
    }
}
