package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionParser;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.PublicKey;

import static net.ripe.rpki.commons.validation.ValidationString.*;

public class X509RouterCertificateParser extends X509CertificateParser<X509RouterCertificate> {

    @Override
    public X509RouterCertificate getCertificate() {
        if (!isSuccess()) {
            throw new IllegalArgumentException(String.format("Router certificate validation failed: %s", result.getFailuresForAllLocations()));
        }
        return new X509RouterCertificate(getX509Certificate());
    }

    @Override
    protected void validatePublicKey() {
        PublicKey publicKey = this.certificate.getPublicKey();
        if (isEcPk(publicKey)) {
            // 3.1.2.  Subject Public Key Info
            //   Refer to Section 3.1 of [RFC8208].
            validateEcSecp256r1Pk();
        } else {
            result.error(PUBLIC_KEY_CERT_ALGORITHM, publicKey.getAlgorithm());
        }
    }

    @Override
    protected void doTypeSpecificValidation() {
        // BGPsec speakers are EEs (CA bit is false, path length constraint MUST NOT be present [RFC6487]).
        result.rejectIfFalse(certificate.getBasicConstraints() == -1, CERT_IS_EE_CERT);

        // BGPsec Router Certificates MUST include the Extended Key Usage (EKU)
        // extension.
        result.rejectIfFalse(isBgpSecExtensionPresent(), BGPSEC_EXT_PRESENT);

        // BGPsec Router Certificates MUST NOT include the SIA extension.
        final X509CertificateInformationAccessDescriptor[] sia = X509CertificateUtil.getSubjectInformationAccess(this.certificate);
        result.rejectIfTrue(sia != null && sia.length > 0, CERT_SIA_IS_PRESENT);

        // BGPsec Router Certificates MUST NOT include the IP Resources extension.
        result.rejectIfTrue(isIpResourceExtensionPresent(), IP_RESOURCE_PRESENT);
        // BGPsec Router Certificates MUST include the AS Resources extension.
        if (result.rejectIfFalse(isAsResourceExtensionPresent(), AS_RESOURCE_PRESENT)) {
            validateAsResourcesValue();
        }

        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(this.certificate.getPublicKey().getEncoded());
        result.rejectIfTrue(subjectPublicKeyInfo == null, CERT_NO_SUBJECT_PK_INFO);
    }

    /**
     * The AS Resources extension MUST include one or more ASNs, and the inherit" element MUST NOT be specified.
     */
    private void validateAsResourcesValue() {
        final ResourceExtensionParser parser = new ResourceExtensionParser();
        // null iff inherited
        final IpResourceSet parsedAsExtension = parser.parseAsIdentifiers(certificate.getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId()));

        if (result.rejectIfFalse(parsedAsExtension != null, BGPSEC_INHERITS_RESOURCES)) {
            result.rejectIfTrue(parsedAsExtension.isEmpty(), BGPSEC_RESOURCES_EMPTY);
        }
    }
}
