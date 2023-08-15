package net.ripe.rpki.commons.provisioning.x509.pkcs10;

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;
import java.util.Enumeration;


/**
 * Helper class to parse PKCS10CertificationRequests for RPKI CA certificates providing convenient
 * accessors to information needed in this domain.
 */
public class RpkiCaCertificateRequestParser {

    private static final String DEFAULT_SIGNATURE_PROVIDER = "SunRsaSign";

    private final JcaPKCS10CertificationRequest pkcs10CertificationRequest;

    private URI caRepositoryUri;

    private URI manifestUri;

    private URI notificationUri;

    private PublicKey publicKey;

    public RpkiCaCertificateRequestParser(PKCS10CertificationRequest pkcs10CertificationRequest) throws RpkiCaCertificateRequestParserException {
        this.pkcs10CertificationRequest = new JcaPKCS10CertificationRequest(pkcs10CertificationRequest);
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

    public URI getNotificationUri() {
        return notificationUri;
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
            publicKey = pkcs10CertificationRequest.getPublicKey();
        } catch (Exception e) {
            throw new RpkiCaCertificateRequestParserException(e);
        }
    }

    private void extractSiaUris() throws RpkiCaCertificateRequestParserException {
        try {
            Extensions extensions = getPkcs9Extensions();
            Extension extension = extensions.getExtension(Extension.subjectInfoAccess);

            ASN1Sequence accessDescriptorSequence = (ASN1Sequence) ASN1Sequence.fromByteArray(extension.getExtnValue().getOctets());

            @SuppressWarnings("unchecked")
            Enumeration<DERSequence> objects = accessDescriptorSequence.getObjects();
            while (objects.hasMoreElements()) {
                AccessDescription accessDescription = AccessDescription.getInstance(objects.nextElement());
                X509CertificateInformationAccessDescriptor accessDescriptor = new X509CertificateInformationAccessDescriptor(accessDescription);
                ASN1ObjectIdentifier oid = accessDescriptor.getMethod();
                if (oid.equals(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY)) {
                    caRepositoryUri = accessDescriptor.getLocation();
                } else if (oid.equals(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST)) {
                    manifestUri = accessDescriptor.getLocation();
                } else if (oid.equals(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY)) {
                    notificationUri = accessDescriptor.getLocation();
                }else {
                    throw new RpkiCaCertificateRequestParserException("Don't understand access descriptor using method: " + oid);
                }
            }
        } catch (IOException e) {
            throw new RpkiCaCertificateRequestParserException(e);
        }

    }

    private Extensions getPkcs9Extensions() throws RpkiCaCertificateRequestParserException {
        ASN1Set pkcs9ExtensionRequest = getPkcs9ExtensionRequest();

        Object extensionRequestElement = pkcs9ExtensionRequest.getObjects().nextElement();
        if (extensionRequestElement instanceof Extensions extensions) {
            return extensions;
        } else if (extensionRequestElement instanceof ASN1Sequence) {
            return Extensions.getInstance(extensionRequestElement);
        } else {
            throw new RpkiCaCertificateRequestParserException("Encountered an element I do not understand, type: "
                    + extensionRequestElement.getClass().getSimpleName());
        }

    }

    private ASN1Set getPkcs9ExtensionRequest() throws RpkiCaCertificateRequestParserException {
        Attribute[] attributes = pkcs10CertificationRequest.getAttributes();

        for (Attribute attr : attributes) {
            ASN1ObjectIdentifier oid = attr.getAttrType();
            if (oid.equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                return attr.getAttrValues();
            }
        }
        throw new RpkiCaCertificateRequestParserException("Could not find PKCS 9 Extension Request");
    }

    private void verifyRequest() throws RpkiCaCertificateRequestParserException {
        try {
            ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(DEFAULT_SIGNATURE_PROVIDER).build(publicKey);
            if (!pkcs10CertificationRequest.isSignatureValid(contentVerifierProvider)) {
                throw new RpkiCaCertificateRequestParserException("signature validation failed");
            }
        } catch (OperatorCreationException | PKCSException e) {
            throw new RpkiCaCertificateRequestParserException("Could not verify request", e);
        }
    }
}
