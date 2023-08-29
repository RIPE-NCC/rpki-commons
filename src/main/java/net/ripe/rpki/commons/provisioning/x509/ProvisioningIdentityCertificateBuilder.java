package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;


public class ProvisioningIdentityCertificateBuilder {

    private static final int DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW = 10;

    private final X509CertificateBuilderHelper builderHelper;

    private KeyPair selfSigningKeyPair;
    private X500Principal selfSigningSubject;
    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;


    public ProvisioningIdentityCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();
    }

    public ProvisioningIdentityCertificateBuilder withSelfSigningKeyPair(KeyPair selfSigningKeyPair) {
        this.selfSigningKeyPair = selfSigningKeyPair;
        return this;
    }

    public ProvisioningIdentityCertificateBuilder withSelfSigningSubject(X500Principal selfSigningSubject) {
        this.selfSigningSubject = selfSigningSubject;
        return this;
    }

    /**
     * Only call this if you need to use a special signature provider, e.g. for HSM. Leave to use default otherwise
     * <p>{@link X509CertificateBuilderHelper#DEFAULT_SIGNATURE_PROVIDER}</p>
     */
    public ProvisioningIdentityCertificateBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public ProvisioningIdentityCertificate build() {
        Validate.notNull(selfSigningKeyPair, "Self Signing KeyPair is required");
        Validate.notNull(selfSigningSubject, "Self Signing DN is required");
        Validate.notNull(signatureProvider, "Signature Provider is required");
        setUpImplicitRequirementsForBuilderHelper();
        builderHelper.withPublicKey(selfSigningKeyPair.getPublic());
        builderHelper.withSigningKeyPair(selfSigningKeyPair);
        builderHelper.withSubjectDN(selfSigningSubject);
        builderHelper.withIssuerDN(selfSigningSubject);
        builderHelper.withSignatureProvider(signatureProvider);
        return new ProvisioningIdentityCertificate(builderHelper.generateCertificate());
    }

    private void setUpImplicitRequirementsForBuilderHelper() {
        builderHelper.withSerial(BigInteger.ONE); // Self-signed! So this is the first!
        var now = OffsetDateTime.now(ZoneOffset.UTC);
        builderHelper.withValidityPeriod(new ValidityPeriod(now, now.plusYears(DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW)));
        builderHelper.withCa(true);
        builderHelper.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }
}
