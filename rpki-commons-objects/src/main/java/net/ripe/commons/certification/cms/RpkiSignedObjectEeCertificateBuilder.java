package net.ripe.commons.certification.cms;


import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.ipresource.InheritedIpResourceSet;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

public class RpkiSignedObjectEeCertificateBuilder {
    
    private URI parentResourceCertificatePublicationUri;
    private URI crlPublicationUri;
    private URI cmsPublicationUri;
    
    private X509ResourceCertificate parentResourceCertificate;
    private KeyPair parentKeyPair;
    
    private KeyPair eeKeyPair;
    private BigInteger serialNumber;
    private ValidityPeriod validityPeriod;
    private X500Principal subject;
    
    private String signatureAlgorithm;
    private String signatureProvider;

    public RpkiSignedObjectEeCertificateBuilder withParentResourceCertificatePublicationUri(URI parentResourceCertificatePublicationUri) {
        this.parentResourceCertificatePublicationUri = parentResourceCertificatePublicationUri;
        return this;
    }

    public RpkiSignedObjectEeCertificateBuilder withCrlPublicationUri(URI crlPublicationUri) {
        this.crlPublicationUri = crlPublicationUri;
        return this;
    }

    public RpkiSignedObjectEeCertificateBuilder withParentResourceCertificate(X509ResourceCertificate parentResourceCertificate) {
        this.parentResourceCertificate = parentResourceCertificate;
        return this;
    }

    public RpkiSignedObjectEeCertificateBuilder withParentKeyPair(KeyPair parentKeyPair) {
        this.parentKeyPair = parentKeyPair;
        return this;
    }
    
    public RpkiSignedObjectEeCertificateBuilder withEeKeyPair(KeyPair eeKeyPair) {
        this.eeKeyPair = eeKeyPair;
        return this;
    }

    public RpkiSignedObjectEeCertificateBuilder withSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public RpkiSignedObjectEeCertificateBuilder withCorrespondingCmsPublicationPoint(URI cmsPublicationUri) {
        this.cmsPublicationUri = cmsPublicationUri;
        return this;
    }
    
    public RpkiSignedObjectEeCertificateBuilder withValidityPeriod(ValidityPeriod validityPeriod) {
        this.validityPeriod = validityPeriod;
        return this;
    }
    
    public RpkiSignedObjectEeCertificateBuilder withSubject(X500Principal certificateSubject) {
        this.subject = certificateSubject;
        return this;
    }
    
    public RpkiSignedObjectEeCertificateBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public RpkiSignedObjectEeCertificateBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public X509ResourceCertificate build() {
        validateFields();


        X509ResourceCertificateBuilder eeCertificateBuilder = new X509ResourceCertificateBuilder();

        X509CertificateInformationAccessDescriptor[] aiaDescriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, parentResourceCertificatePublicationUri)
        };

        eeCertificateBuilder.withAuthorityInformationAccess(aiaDescriptors);
        eeCertificateBuilder.withCrlDistributionPoints(crlPublicationUri);
        eeCertificateBuilder.withCa(false);
        eeCertificateBuilder.withKeyUsage(KeyUsage.digitalSignature);
        eeCertificateBuilder.withAuthorityKeyIdentifier(true);
        eeCertificateBuilder.withIssuerDN(parentResourceCertificate.getSubject());
        eeCertificateBuilder.withSignatureAlgorithm(signatureAlgorithm);
        eeCertificateBuilder.withSignatureProvider(signatureProvider);
        eeCertificateBuilder.withPublicKey(eeKeyPair.getPublic());
        eeCertificateBuilder.withResources(InheritedIpResourceSet.getInstance());
        eeCertificateBuilder.withSerial(serialNumber);
        eeCertificateBuilder.withSigningKeyPair(parentKeyPair);
        eeCertificateBuilder.withSubjectDN(subject);

        X509CertificateInformationAccessDescriptor[] siaDescriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, cmsPublicationUri)
        };

        eeCertificateBuilder.withSubjectInformationAccess(siaDescriptors);
        eeCertificateBuilder.withSubjectKeyIdentifier(true);
        eeCertificateBuilder.withValidityPeriod(validityPeriod);

        return eeCertificateBuilder.build();
    }

    private void validateFields() {
        Validate.notNull(parentResourceCertificatePublicationUri, "Resource Certificate Publication URI is required");
        Validate.notNull(crlPublicationUri, "CRL Publication URI is required");
        Validate.notNull(parentResourceCertificate, "Parent resource certificate is required");
        Validate.notNull(parentKeyPair, "Parent keyPair is required");
        Validate.notNull(eeKeyPair, "EE keyPair is required");
        Validate.notNull(serialNumber, "Serial number is required");
        Validate.notNull(cmsPublicationUri, "Manifest URI is required");
        Validate.notNull(validityPeriod, "Validity Period is required");
        Validate.notNull(subject, "Subject is required");
        Validate.notNull(signatureAlgorithm, "SignatureAlgorithm is required");
        Validate.notNull(signatureProvider, "SignatureProvider is required");
    }








}
