package net.ripe.commons.provisioning.x509.pkcs10;

import java.net.URI;
import java.security.KeyPair;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;


/**
 * Builder for PKCS10CertificationRequests for RPKI CA certificates.
 */
public class RpkiCaCertificateRequestBuilder {

    private X500Principal subject;

    private URI caRepositoryUri;

    private URI manifestUri;

    private String signatureAlgorithm = "SHA256withRSA";

    private String signatureProvider = "SunRsaSign";

    public RpkiCaCertificateRequestBuilder withSubject(X500Principal subject) {
        this.subject = subject;
        return this;
    }

    public RpkiCaCertificateRequestBuilder withCaRepositoryUri(URI caRepositoryUri) {
        this.caRepositoryUri = caRepositoryUri;
        return this;
    }

    public RpkiCaCertificateRequestBuilder withManifestUri(URI manifestUri) {
        this.manifestUri = manifestUri;
        return this;
    }

    /**
     * Default: SunRsaSign
     * @return 
     */
    public RpkiCaCertificateRequestBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    /**
     * Default: SHA256withRSA
     * @return 
     */
    public RpkiCaCertificateRequestBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public PKCS10CertificationRequest build(KeyPair keyPair) {
        try {
            X509Extensions extensions = createSiaExtensions();

            Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));

            return new PKCS10CertificationRequest(
                    signatureAlgorithm,
                    subject,
                    keyPair.getPublic(),
                    new DERSet(attribute),
                    keyPair.getPrivate(),
                    signatureProvider);
        } catch (Exception e) {
            throw new RpkiCaCertificateRequestBuilderException(e);
        }
    }

    private X509Extensions createSiaExtensions() {
        // Make extension for SIA in request. See here:
        // http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
        Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
        Vector<X509Extension> values = new Vector<X509Extension>();

        X509CertificateInformationAccessDescriptor[] descriptors = new X509CertificateInformationAccessDescriptor[] {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, caRepositoryUri),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri),};
        AccessDescription[] subjectInformationAccess = X509CertificateInformationAccessDescriptor.convertAccessDescriptors(descriptors);
        DERSequence derSequence = new DERSequence(subjectInformationAccess);

        oids.add(X509Extensions.SubjectInfoAccess);
        X509Extension siaExtension = new X509Extension(false, new DEROctetString(derSequence.getDEREncoded()));
        values.add(siaExtension);

        return new X509Extensions(oids, values);
    }
}
