package net.ripe.rpki.commons.crypto.x509cert;

import org.bouncycastle.asn1.x509.KeyUsage;

import java.net.URI;

import static java.util.Objects.requireNonNull;

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

        X509ResourceCertificateBuilder builder = createGenericRpkiCertificateBuilder(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        // Implicitly required by standards
        builder.withCa(true);
        builder.withAuthorityKeyIdentifier(true);

        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri)};

        builder.withSubjectInformationAccess(descriptors);

        return builder.build();
    }


    @Override
    protected void validateFields() {
        super.validateFields();

        requireNonNull(caRepositoryUri, "CA Repository URI is required");
        requireNonNull(manifestUri, "Manifest URI is required");
    }
}
