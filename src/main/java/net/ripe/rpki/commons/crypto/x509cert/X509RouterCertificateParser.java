package net.ripe.rpki.commons.crypto.x509cert;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.security.PublicKey;

import static net.ripe.rpki.commons.validation.ValidationString.AS_RESOURCE_PRESENT;
import static net.ripe.rpki.commons.validation.ValidationString.BGPSEC_EXT_PRESENT;
import static net.ripe.rpki.commons.validation.ValidationString.CERT_NO_SUBJECT_PK_INFO;
import static net.ripe.rpki.commons.validation.ValidationString.CERT_SIA_IS_PRESENT;
import static net.ripe.rpki.commons.validation.ValidationString.IP_RESOURCE_PRESENT;
import static net.ripe.rpki.commons.validation.ValidationString.PUBLIC_KEY_CERT_ALGORITHM;

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
        if (isRsaPk(publicKey)) {
            super.validateRsaPk();
        } else if (isEcPk(publicKey)) {
            validateEcPk();
        } else {
            result.error(PUBLIC_KEY_CERT_ALGORITHM, publicKey.getAlgorithm());
        }
    }

    @Override
    protected void doTypeSpecificValidation() {
        result.rejectIfFalse(isBgpSecExtensionPresent(), BGPSEC_EXT_PRESENT);

        final X509CertificateInformationAccessDescriptor[] sia = X509CertificateUtil.getSubjectInformationAccess(this.certificate);
        result.rejectIfTrue(sia != null && sia.length > 0, CERT_SIA_IS_PRESENT);

        result.rejectIfTrue(isIpResourceExtensionPresent(), IP_RESOURCE_PRESENT);
        result.rejectIfFalse(isAsResourceExtensionPresent(), AS_RESOURCE_PRESENT);

        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(this.certificate.getPublicKey().getEncoded());
        result.rejectIfTrue(subjectPublicKeyInfo == null, CERT_NO_SUBJECT_PK_INFO);
    }
}
