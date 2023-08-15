package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.x509.PolicyInformation;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.EnumSet;

/**
 * Generic Builder for X509RouterCertificates.
 */
public class X509RouterCertificateBuilder {

    private final X509CertificateBuilderHelper builderHelper;
    private int[] asns;

    public X509RouterCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
        builderHelper.withPolicies(X509ResourceCertificate.POLICY_INFORMATION);
    }

    public X509RouterCertificateBuilder withSignatureProvider(String signatureProvider) {
        builderHelper.withSignatureProvider(signatureProvider);
        return this;
    }

    public X509RouterCertificateBuilder withSerial(BigInteger serial) {
        builderHelper.withSerial(serial);
        return this;
    }

    public X509RouterCertificateBuilder withSubjectDN(X500Principal subjectDN) {
        builderHelper.withSubjectDN(subjectDN);
        return this;
    }

    public X509RouterCertificateBuilder withIssuerDN(X500Principal issuerDN) {
        builderHelper.withIssuerDN(issuerDN);
        return this;
    }

    public X509RouterCertificateBuilder withValidityPeriod(ValidityPeriod validityPeriod) {
        builderHelper.withValidityPeriod(validityPeriod);
        return this;
    }

    public X509RouterCertificateBuilder withPublicKey(PublicKey publicKey) {
        builderHelper.withPublicKey(publicKey);
        return this;
    }

    public X509RouterCertificateBuilder withSigningKeyPair(KeyPair signingKey) {
        builderHelper.withSigningKeyPair(signingKey);
        return this;
    }

    public X509RouterCertificateBuilder withKeyUsage(int keyUsage) {
        builderHelper.withKeyUsage(keyUsage);
        return this;
    }

    public X509RouterCertificateBuilder withAsns(int[] asns) {
        this.asns = asns;
        if (asns != null) {
            final IpResourceSet resources = new IpResourceSet();
            for (int asn : asns) {
                resources.add(new Asn(asn));
            }
            builderHelper.withResources(resources);
        }
        return this;
    }

    public X509RouterCertificateBuilder withCa(boolean ca) {
        builderHelper.withCa(ca);
        return this;
    }

    public X509RouterCertificateBuilder withAuthorityKeyIdentifier(boolean add) {
        builderHelper.withAuthorityKeyIdentifier(add);
        return this;
    }

    public X509RouterCertificateBuilder withCrlDistributionPoints(URI... uris) {
        builderHelper.withCrlDistributionPoints(uris);
        return this;
    }

    public X509RouterCertificateBuilder withAuthorityInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        builderHelper.withAuthorityInformationAccess(descriptors);
        return this;
    }

    public X509RouterCertificateBuilder withSubjectInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        builderHelper.withSubjectInformationAccess(descriptors);
        return this;
    }

    public X509RouterCertificateBuilder withPolicies(PolicyInformation... policies) {
        builderHelper.withPolicies(policies);
        return this;
    }

    public X509RouterCertificate build() {
        Validate.notNull(asns, "no AS resources");
        Validate.isTrue(asns.length > 0, "empty AS resources");
        builderHelper.withRouter(true);
        return new X509RouterCertificate(builderHelper.generateCertificate());
    }

    public X509RouterCertificateBuilder withInheritedResourceTypes(EnumSet<IpResourceType> resourceTypes) {
        builderHelper.withInheritedResourceTypes(resourceTypes);
        return this;
    }
}
