package net.ripe.rpki.commons.crypto.x509cert;

import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.net.URI;

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

        X509ResourceCertificateBuilder builder = createGenericRpkiCertificateBuilder(KeyUsage.digitalSignature);

        // Implicit by standard:
        builder.withCa(false);

        X509CertificateInformationAccessDescriptor[] siaDescriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, cmsPublicationUri)
        };
        builder.withSubjectInformationAccess(siaDescriptors);

        return builder.build();
    }

    @Override
    protected void validateFields() {
        super.validateFields();
        Validate.isTrue(!isSelfSigned(), "EE Certificate can not be self-signed (use EE keypair for public and signing the object, sign this cert with parent key pair)");
        Validate.notNull(cmsPublicationUri, "CMS Object Publication URI is required");
    }
}
