package net.ripe.commons.certification.x509cert;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;

public abstract class GenericRpkiCertificateBuilder {

    private PublicKey publicKey;
    private KeyPair signingKeyPair;
    private BigInteger serial;
    private IpResourceSet resources;
    private X500Principal subject;
    private X500Principal issuer;
    private ValidityPeriod validityPeriod;
    
    private URI crlUri;
    private URI parentResourceCertificatePublicationUri;
    
    private String signatureAlgorithm = "SHA256withRSA"; 
    private String signatureProvider = "SunRsaSign";
    
    public void withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void withSigningKeyPair(KeyPair signingKeyPair) {
        this.signingKeyPair = signingKeyPair;
    }

    public void withSerial(BigInteger serial) {
        this.serial = serial;
    }

    public void withResources(IpResourceSet resources) {
        this.resources = resources;
    }

    public void withSubjectDN(X500Principal subject) {
        this.subject = subject;
    }

    public void withIssuerDN(X500Principal issuer) {
        this.issuer = issuer;
    }

    public void withValidityPeriod(ValidityPeriod validityPeriod) {
        this.validityPeriod = validityPeriod;
    }


    public void withCrlUri(URI crlUri) {
        Validate.notNull(crlUri, "CRL Uri can not be null");
        validateIsRsyncUri(crlUri);
        this.crlUri = crlUri;
    }

    protected void validateIsRsyncUri(URI crlUri) {
        Validate.isTrue(crlUri.toString().startsWith("rsync:"), "Rsync URI is required, multiple repositories not supported by this builder at this time");
    }

    protected boolean isSelfSigned() {
        return signingKeyPair.getPublic().equals(publicKey);
    }

    public void withParentResourceCertificatePublicationUri(URI parentResourceCertificatePublicationUri) {
        this.parentResourceCertificatePublicationUri = parentResourceCertificatePublicationUri;
    }

    /**
     * Default: "SHA256withRSA"
     */
    public void withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Default: SunRsaSign
     */
    public void withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
    }
    
    protected X509ResourceCertificateBuilder createGenericRpkiCertificateBuilder() {
        
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        
        builder.withPublicKey(publicKey);
        builder.withSigningKeyPair(signingKeyPair);
        
        builder.withSerial(serial);
        
        builder.withResources(resources);
        
        builder.withSubjectDN(subject);
        builder.withIssuerDN(issuer);
        
        builder.withValidityPeriod(validityPeriod);
        
        if(!isSelfSigned()) {
            builder.withCrlDistributionPoints(crlUri);
            
            X509CertificateInformationAccessDescriptor[] aiaDescriptors = {
                    new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, parentResourceCertificatePublicationUri)
            };
            builder.withAuthorityInformationAccess(aiaDescriptors);
            builder.withAuthorityKeyIdentifier(true);
        }
        
        builder.withSignatureAlgorithm(signatureAlgorithm);
        builder.withSignatureProvider(signatureProvider);
        
        builder.withSubjectKeyIdentifier(true);
        
        return builder;
    }

    protected void validateFields() {
        Validate.notNull(publicKey, "Public Key is required");
        Validate.notNull(signingKeyPair, "Signing Key Pair is required");
        Validate.notNull(serial, "Serial is required");
        Validate.notNull(resources, "Resources are required. Inherited resources are allowed but not advised (unless you are building an EE cert for manifests)");
        Validate.notNull(subject, "Subject is required");
        Validate.notNull(issuer, "Issuer is required");
        Validate.notNull(validityPeriod, "ValidityPeriod is required");
        
        
        if (!isSelfSigned()) {
            Validate.notNull(crlUri, "CRL URI is required (except for self-signed (root) certificates)");
            Validate.notNull(parentResourceCertificatePublicationUri, "Parent Certificate Publication URI is required");
        }
        
        Validate.notNull(signatureAlgorithm, "SignatureAlgorithm is required");
        Validate.notNull(signatureProvider, "SignatureProvider is required");
    }
    

}
