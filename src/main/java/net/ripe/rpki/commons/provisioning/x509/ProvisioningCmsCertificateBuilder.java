package net.ripe.rpki.commons.provisioning.x509;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;


public class ProvisioningCmsCertificateBuilder {

    private static final int DEFAULT_VALIDITY_TIME_MINUTES_FROM_NOW = 15;
    /** default validity before now - to compensate for clock drift */
    private static final int DEFAULT_VALIDITY_TIME_MINUTES_BEFORE_NOW = 1;

    private X509CertificateBuilderHelper builderHelper;

    public ProvisioningCmsCertificateBuilder() {
        builderHelper = new X509CertificateBuilderHelper();

        final DateTime now = UTC.dateTime();
        builderHelper.withValidityPeriod(new ValidityPeriod(now.minusMinutes(DEFAULT_VALIDITY_TIME_MINUTES_BEFORE_NOW), now.plusMinutes(DEFAULT_VALIDITY_TIME_MINUTES_FROM_NOW)));
    }

    public ProvisioningCmsCertificateBuilder withSignatureProvider(String signatureProvider) {
        builderHelper.withSignatureProvider(signatureProvider);
        return this;
    }

    public ProvisioningCmsCertificateBuilder withSerial(BigInteger serial) {
        builderHelper.withSerial(serial);
        return this;
    }

    public ProvisioningCmsCertificateBuilder withSubjectDN(X500Principal subjectDN) {
        builderHelper.withSubjectDN(subjectDN);
        return this;
    }

    public ProvisioningCmsCertificateBuilder withIssuerDN(X500Principal issuerDN) {
        builderHelper.withIssuerDN(issuerDN);
        return this;
    }

    public ProvisioningCmsCertificateBuilder withPublicKey(PublicKey publicKey) {
        builderHelper.withPublicKey(publicKey);
        return this;
    }

    public ProvisioningCmsCertificateBuilder withSigningKeyPair(KeyPair signingKey) {
        builderHelper.withSigningKeyPair(signingKey);
        return this;
    }

    /**
     * Override the <emph>default</emph> validity period of this EE certificate.
     */
    public ProvisioningCmsCertificateBuilder withValidityPeriod(ValidityPeriod validityPeriod) {
        builderHelper.withValidityPeriod(validityPeriod);
        return this;
    }

    public ProvisioningCmsCertificate build() {
        setUpImplicitRequirementsForBuilderHelper();
        return new ProvisioningCmsCertificate(builderHelper.generateCertificate());
    }

    private void setUpImplicitRequirementsForBuilderHelper() {
        builderHelper.withCa(false);
        builderHelper.withKeyUsage(KeyUsage.digitalSignature);
        builderHelper.withAuthorityKeyIdentifier(true);
    }
}