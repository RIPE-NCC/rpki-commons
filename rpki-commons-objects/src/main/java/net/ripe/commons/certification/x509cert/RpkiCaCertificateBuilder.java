package net.ripe.commons.certification.x509cert;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Builder for X509ResourceCertificates used by RPKI CAs
 */
// TODO: Stop chaining, and mkae common parent to this and EeCertBuilder, unit test... (this is now lacking signature provider)
public class RpkiCaCertificateBuilder {

    private PublicKey publicKey;
    private KeyPair signingKeyPair;
    private BigInteger serial;
    private IpResourceSet resources;
    private X500Principal subject;
    private X500Principal issuer;
    private ValidityPeriod validityPeriod;
    private URI caRepositoryUri;
    private URI manifestUri;
    private URI crlUri;

    public RpkiCaCertificateBuilder withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }
    
    public RpkiCaCertificateBuilder withSigningKeyPair(KeyPair signingKeyPair) {
        this.signingKeyPair = signingKeyPair;
        return this;
    }

    public RpkiCaCertificateBuilder withSerial(BigInteger serial) {
        this.serial = serial;
        return this;
    }
    
    public RpkiCaCertificateBuilder withResources(IpResourceSet resources) {
        this.resources = resources;
        return this;
    }

    public RpkiCaCertificateBuilder withSubjectDN(X500Principal subject) {
        this.subject = subject;
        return this;
    }
    
    public RpkiCaCertificateBuilder withIssuerDN(X500Principal issuer) {
        this.issuer = issuer;
        return this;
    }
    
    public RpkiCaCertificateBuilder withValidityPeriod(ValidityPeriod validityPeriod) {
        this.validityPeriod = validityPeriod;
        return this;
    }
    
    public RpkiCaCertificateBuilder withCaRepositoryUri(URI caRepositoryUri) {
        validateIsRsyncUri(caRepositoryUri);
        this.caRepositoryUri = caRepositoryUri;
        return this;
    }
    
    public RpkiCaCertificateBuilder withManifestUri(URI manifestUri) {
        validateIsRsyncUri(manifestUri);
        this.manifestUri = manifestUri;
        return this;
    }

    public RpkiCaCertificateBuilder withCrlUri(URI crlUri) {
        validateIsRsyncUri(crlUri);
        this.crlUri = crlUri;
        return this;
    }

    private void validateIsRsyncUri(URI crlUri) {
        Validate.isTrue(crlUri.toString().startsWith("rsync:"), "Rsync URI is required, multiple repositories not supported by this builder at this time");
    }

    
    

    public X509ResourceCertificate build() {
        validateFields();
        
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        
        // Implicitly required by standards
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withAuthorityKeyIdentifier(true);
        
        builder.withPublicKey(publicKey);
        builder.withSigningKeyPair(signingKeyPair);
        
        builder.withSerial(serial);
        
        builder.withResources(resources);
        
        builder.withSubjectDN(subject);
        builder.withIssuerDN(issuer);
        
        builder.withValidityPeriod(validityPeriod);
        
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri)};

        builder.withSubjectInformationAccess(descriptors);
        
        return builder.build();
    }

    private void validateFields() {
        Validate.notNull(publicKey, "Public Key is required");
        Validate.notNull(signingKeyPair, "Signing Key Pair is required");
        Validate.notNull(serial, "Serial is required");
        Validate.notNull(resources, "Resources are required. Inherited resources are allowed but not advised");
        Validate.notNull(subject, "Subject is required");
        Validate.notNull(issuer, "Issuer is required");
        Validate.notNull(validityPeriod, "ValidityPeriod is required");
        Validate.notNull(caRepositoryUri, "CA Repository URI is required");
        Validate.notNull(manifestUri, "Manifest URI is required");
        Validate.notNull(crlUri, "CRL URI is required");
    }












    
    
    
}
