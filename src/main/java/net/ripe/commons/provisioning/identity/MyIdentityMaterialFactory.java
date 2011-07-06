package net.ripe.commons.provisioning.identity;

import java.math.BigInteger;
import java.security.KeyPair;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilder;

public class MyIdentityMaterialFactory {

    public MyIdentityMaterial createNew(ProvisioningSubjectNamingStrategy namingStrategy) {

        KeyPair identityKeyPair = ProvisioningKeyPairGenerator.generate();
        ProvisioningIdentityCertificate identityCertificate = createSelfSignedProvisioningIdentityCertificate(identityKeyPair, namingStrategy);
        X509Crl identityCrl = createIdentityCrl(identityCertificate, identityKeyPair);

        return new MyIdentityMaterial(identityKeyPair, identityCrl, identityCertificate);
    }

    private ProvisioningIdentityCertificate createSelfSignedProvisioningIdentityCertificate(KeyPair identityKeyPair, ProvisioningSubjectNamingStrategy namingStrategy) {
        ProvisioningIdentityCertificateBuilder builder = new ProvisioningIdentityCertificateBuilder();
        builder.withSelfSigningKeyPair(identityKeyPair);
        builder.withSelfSigningSubject(namingStrategy.getCertificateSubject(identityKeyPair.getPublic()));

        return builder.build();
    }

    private X509Crl createIdentityCrl(ProvisioningIdentityCertificate certificate, KeyPair keyPair) {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withAuthorityKeyIdentifier(keyPair.getPublic());
        builder.withIssuerDN(certificate.getIssuer());
        builder.withThisUpdateTime(certificate.getValidityPeriod().getNotValidBefore());
        builder.withNextUpdateTime(certificate.getValidityPeriod().getNotValidAfter());
        builder.withNumber(BigInteger.ONE);
        builder.withSignatureProvider(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER);
        return builder.build(keyPair.getPrivate());
    }
}
