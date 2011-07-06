package net.ripe.commons.certification.x509cert;


import java.net.URI;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Builder for Embedded EE Certificates used in RpkiSignedObjects
 */
public class RpkiSignedObjectEeCertificateBuilder extends GenericRpkiCertificateBuilder {
    
    private URI cmsPublicationUri;
    
    public void withCorrespondingCmsPublicationPoint(URI cmsPublicationUri) {
        this.cmsPublicationUri = cmsPublicationUri;
    }
        
    public X509ResourceCertificate build() {
        validateFields();

        X509ResourceCertificateBuilder builder = createGenericRpkiCertificateBuilder();
        
        // Implicit by standard:
        builder.withCa(false);
        builder.withKeyUsage(KeyUsage.digitalSignature);
        
        X509CertificateInformationAccessDescriptor[] siaDescriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, cmsPublicationUri)
        };
        builder.withSubjectInformationAccess(siaDescriptors);

        return builder.build();
    }

    protected void validateFields() {
        super.validateFields();
        Validate.isTrue(!isSelfSigned(),"EE Certificate can not be self-signed (use EE keypair for public and signing the object, sign this cert with parent key pair)");
        Validate.notNull(cmsPublicationUri, "CMS Object Publication URI is required");
        
    }








}
