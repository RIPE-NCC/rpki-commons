package net.ripe.commons.certification.x509cert;




import java.net.URI;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Builder for X509ResourceCertificates used by RPKI CAs
 */
public class RpkiCaCertificateBuilder extends GenericRpkiCertificateBuilder {
    
    private URI caRepositoryUri;
    private URI manifestUri;

    public void withCaRepositoryUri(URI caRepositoryUri) {
        validateIsRsyncUri(caRepositoryUri);
        this.caRepositoryUri = caRepositoryUri;
    }

    public void withManifestUri(URI manifestUri) {
        validateIsRsyncUri(manifestUri);
        this.manifestUri = manifestUri;
    }
    
    public X509ResourceCertificate build() {
        validateFields();
        
        X509ResourceCertificateBuilder builder = createGenericRpkiCertificateBuilder();
        
        // Implicitly required by standards
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withAuthorityKeyIdentifier(true);
        
        
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri)};

        builder.withSubjectInformationAccess(descriptors);
        
        return builder.build();
    }



    protected void validateFields() {
        super.validateFields();
        
        Validate.notNull(caRepositoryUri, "CA Repository URI is required");
        Validate.notNull(manifestUri, "Manifest URI is required");

    }












    
    
    
}
