package net.ripe.commons.provisioning.x509.pkcs10;

import java.net.URI;
import java.security.PublicKey;
import java.util.Enumeration;

import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;


/**
 * Helper class to parse PKCS10CertificationRequests for RPKI CA certificates providing convenient
 * accessors to information needed in this domain.
 */
public class RpkiCaCertificateRequestParser {

    private static final String DEFAULT_SIGNATURE_PROVIDER = "SunRsaSign";

    private PKCS10CertificationRequest pkcs10CertificationRequest;

    private URI caRepositoryUri;

    private URI manifestUri;

    private PublicKey publicKey;

    public RpkiCaCertificateRequestParser(PKCS10CertificationRequest pkcs10CertificationRequest) throws RpkiCaCertificateRequestParserException {
        this.pkcs10CertificationRequest = pkcs10CertificationRequest;
        process();

        if (caRepositoryUri == null) {
            throw new RpkiCaCertificateRequestParserException("No CA Repository URI included in SIA in request");
        }
        if (manifestUri == null) {
            throw new RpkiCaCertificateRequestParserException("No Manifest URI included in SIA in request");
        }
        if (publicKey == null) {
            throw new RpkiCaCertificateRequestParserException("No Public Key included in request");
        }
    }

    public URI getCaRepositoryUri() {
        return caRepositoryUri;
    }

    public URI getManifestUri() {
        return manifestUri;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private void process() throws RpkiCaCertificateRequestParserException {
        extractPublicKey();
        extractSiaUris();
        verifyRequest();
    }

    private void extractPublicKey() throws RpkiCaCertificateRequestParserException {
        try {
            publicKey = pkcs10CertificationRequest.getPublicKey(DEFAULT_SIGNATURE_PROVIDER);
        } catch (Exception e) {
            throw new RpkiCaCertificateRequestParserException(e);
        }
    }

    private void extractSiaUris() throws RpkiCaCertificateRequestParserException {
        try {
            X509Extensions extensions = getPkcs9Extensions();
            X509Extension extension = extensions.getExtension(X509Extensions.SubjectInfoAccess);

            DERSequence accessDescriptorSequence = (DERSequence) DERSequence.fromByteArray(extension.getValue().getOctets());

            @SuppressWarnings("unchecked")
            Enumeration<DERSequence> objects = (Enumeration<DERSequence>) accessDescriptorSequence.getObjects();
            while (objects.hasMoreElements()) {
                AccessDescription accessDescription = new AccessDescription(objects.nextElement());
                X509CertificateInformationAccessDescriptor accessDescriptor = new X509CertificateInformationAccessDescriptor(accessDescription);
                DERObjectIdentifier oid = accessDescriptor.getMethod();
                if (oid.equals(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY)) {
                    caRepositoryUri = accessDescriptor.getLocation();
                } else if (oid.equals(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST)) {
                    manifestUri = accessDescriptor.getLocation();
                } else {
                    throw new RpkiCaCertificateRequestParserException("Don't understand access descriptor using method: " + oid);
                }
            }
        } catch (Exception e) {
            throw new RpkiCaCertificateRequestParserException(e);
        }

    }

    private X509Extensions getPkcs9Extensions() throws RpkiCaCertificateRequestParserException {
        DERSet pkcs9ExtensionRequest = getPkcs9ExtensionRequest();

        Object extensionRequestElement = pkcs9ExtensionRequest.getObjects().nextElement();
        if (extensionRequestElement instanceof X509Extensions) {
            return (X509Extensions) extensionRequestElement;
        } else if (extensionRequestElement instanceof DERSequence) {
            return new X509Extensions((DERSequence) extensionRequestElement);
        } else {
            throw new RpkiCaCertificateRequestParserException("Encountered an element I do not understand, type: "
                    + extensionRequestElement.getClass().getSimpleName());
        }

    }

    private DERSet getPkcs9ExtensionRequest() throws RpkiCaCertificateRequestParserException {
        ASN1Set attributes = pkcs10CertificationRequest.getCertificationRequestInfo().getAttributes();

        @SuppressWarnings("unchecked")
        Enumeration<Object> attributeObjects = attributes.getObjects();
        while (attributeObjects.hasMoreElements()) {
            Attribute attr;

            Object nextElement = attributeObjects.nextElement();
            if (nextElement instanceof DERSequence) {
                // When the request is encoded and decoded the Attribute shows up as a DERSequence
                attr = new Attribute((DERSequence) nextElement);
            } else if (nextElement instanceof Attribute) {
                // When we pass a PKCS10CertificationRequest object around without encoding/decoding
                // the type is preserved
                attr = (Attribute) nextElement;
            } else {
                throw new RpkiCaCertificateRequestParserException("Encountered an element I do not understand, type: "
                        + nextElement.getClass().getSimpleName());
            }

            DERObjectIdentifier oid = attr.getAttrType();
            if (oid.equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                return (DERSet) attr.getAttrValues();
            }
        }
        throw new RpkiCaCertificateRequestParserException("Could not find PKCS 9 Extension Request");
    }

    private void verifyRequest() throws RpkiCaCertificateRequestParserException {
        try {
            pkcs10CertificationRequest.verify(publicKey, DEFAULT_SIGNATURE_PROVIDER);
        } catch (Exception e) {
            throw new RpkiCaCertificateRequestParserException("Could not verify request", e);
        }
    }

    
}
