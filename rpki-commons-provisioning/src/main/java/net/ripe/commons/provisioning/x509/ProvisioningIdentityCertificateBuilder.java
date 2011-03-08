package net.ripe.commons.provisioning.x509;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.joda.time.DateTime;


public class ProvisioningIdentityCertificateBuilder {

    private static final String SOFTWARE_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SOFTWARE_SIGNATURE_PROVIDER = "SunRsaSign";

    public ProvisioningIdentityCertificate build(KeyPair selfSigningKeyPair, X500Principal selfSigningDN) {
        Validate.notNull(selfSigningKeyPair, "Self Signing KeyPair is required");
        Validate.notNull(selfSigningDN, "Self Signing DN is required");
        return new ProvisioningIdentityCertificate(generateSelfSignedCertificate(selfSigningKeyPair, selfSigningDN));
    }

    private X509Certificate generateSelfSignedCertificate(KeyPair selfSigningKeyPair, X500Principal selfSigningDN) {
        try {
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.setNotBefore(new Date(new DateTime().getMillis()));
            generator.setNotAfter(new Date(new DateTime().plusYears(10).getMillis()));
            generator.setIssuerDN(selfSigningDN);
            generator.setSerialNumber(BigInteger.ONE);
            generator.setPublicKey(selfSigningKeyPair.getPublic());
            generator.setSignatureAlgorithm(SOFTWARE_SIGNATURE_ALGORITHM);
            generator.setSubjectDN(selfSigningDN);

            generator.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(selfSigningKeyPair.getPublic()));
            generator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(selfSigningKeyPair.getPublic()));
            generator.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            // generator.addExtension(X509Extensions.CertificatePolicies, true, new DERSequence(new
            // DERObjectIdentifier("1.3.6.1.5.5.7.14.2")));
            // TODO: check and add other extensions
            return generator.generate(selfSigningKeyPair.getPrivate(), SOFTWARE_SIGNATURE_PROVIDER);
        } catch (CertificateEncodingException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        } catch (InvalidKeyException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        } catch (IllegalStateException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        } catch (NoSuchProviderException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        } catch (SignatureException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        } catch (CertificateParsingException e) {
            throw new ProvisioningIdentityCertificateBuilderException(e);
        }
    }

}
