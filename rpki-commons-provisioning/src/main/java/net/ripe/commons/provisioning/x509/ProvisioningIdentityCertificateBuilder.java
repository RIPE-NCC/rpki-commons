package net.ripe.commons.provisioning.x509;

import java.math.BigInteger;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;


public class ProvisioningIdentityCertificateBuilder {

    private static final int DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW = 10;

    private X509CertificateBuilderHelper builderHelper;

    private KeyPair selfSigningKeyPair;

    private X500Principal selfSigningSubject;


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

    public ProvisioningIdentityCertificate build() {
        Validate.notNull(selfSigningKeyPair, "Self Signing KeyPair is required");
        Validate.notNull(selfSigningSubject, "Self Signing DN is required");
        setUpImplicitRequirementsForBuilderHelper();
        return new ProvisioningIdentityCertificate(builderHelper.generateCertificate());
    }

    private void setUpImplicitRequirementsForBuilderHelper() {
        builderHelper.withSerial(BigInteger.ONE); // Self-signed! So this is the first!
        builderHelper.withValidityPeriod(new ValidityPeriod(new DateTime(), new DateTime().plusYears(DEFAULT_VALIDITY_TIME_YEARS_FROM_NOW)));
        builderHelper.withCa(true);
        builderHelper.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }
}
