package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc8209.RouterExtensionEncoder;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;

import static net.ripe.rpki.commons.validation.ValidationString.CERTIFICATE_PARSED;
import static net.ripe.rpki.commons.validation.ValidationString.CERTIFICATE_SIGNATURE_ALGORITHM;
import static net.ripe.rpki.commons.validation.ValidationString.PUBLIC_KEY_CERT_ALGORITHM;
import static net.ripe.rpki.commons.validation.ValidationString.PUBLIC_KEY_CERT_SIZE;

public abstract class X509CertificateParser<T extends AbstractX509CertificateWrapper> {

    private static final String[] ALLOWED_SIGNATURE_ALGORITHM_OIDS = {
            PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
    };

    protected X509Certificate certificate;

    protected ValidationResult result;

    public void parse(String location, byte[] encoded) {
        parse(ValidationResult.withLocation(location), encoded);
    }

    public void parse(ValidationResult validationResult, byte[] encoded) {
        this.result = validationResult;
        final X509Certificate certificate = parseEncoded(encoded, result);
        validateX509Certificate(validationResult, certificate);
    }

    public void validateX509Certificate(ValidationResult validationResult, X509Certificate certificate) {
        this.certificate = certificate;
        this.result = validationResult;
        if (!validationResult.hasFailureForCurrentLocation()) {
            validateSignatureAlgorithm();
            validatePublicKey();
            doTypeSpecificValidation();
        }
    }

    public static X509GenericCertificate parseCertificate(ValidationResult result, byte[] encoded) {
        final X509Certificate certificate = parseEncoded(encoded, result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        X509CertificateParser<? extends X509GenericCertificate> parser;
        if (X509CertificateUtil.isRouter(certificate)) {
            parser = new X509RouterCertificateParser();
        } else  {
            parser = new X509ResourceCertificateParser();
        }

        parser.validateX509Certificate(result, certificate);

        return result.hasFailureForCurrentLocation() ? null : parser.getCertificate();
    }

    protected void validatePublicKey() {
        validateRsaPk();
    }

    void validateRsaPk() {
        final PublicKey publicKey = certificate.getPublicKey();
        final boolean rsaPk = isRsaPk(publicKey);
        result.rejectIfFalse(rsaPk, PUBLIC_KEY_CERT_ALGORITHM, publicKey.getAlgorithm());
        if (rsaPk) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            result.warnIfFalse(2048 == rsaPublicKey.getModulus().bitLength(), PUBLIC_KEY_CERT_SIZE, String.valueOf(rsaPublicKey.getModulus().bitLength()));
        }
    }

    boolean isRsaPk(PublicKey publicKey) {
        return "RSA".equals(publicKey.getAlgorithm()) && publicKey instanceof RSAPublicKey;
    }

    boolean isEcPk(PublicKey publicKey) {
        return "EC".equals(publicKey.getAlgorithm()) && publicKey instanceof ECPublicKey;
    }

    void validateEcSecp256r1Pk() {
        final byte[] enc = certificate.getPublicKey().getEncoded();
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(enc));
        final AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        final ASN1ObjectIdentifier algorithmOid = algorithm.getAlgorithm();

        // https://datatracker.ietf.org/doc/html/rfc8208#section-3.1
        // o  algorithm (an AlgorithmIdentifier type): The id-ecPublicKey OID
        // MUST be used in the algorithm field, as specified in Section 2.1.1
        // of [RFC5480].
        if(result.rejectIfFalse(X9ObjectIdentifiers.id_ecPublicKey.equals(algorithmOid), PUBLIC_KEY_CERT_ALGORITHM, algorithmOid.getId())){
            // The value for the associated parameters MUST be
            // secp256r1, as specified in Section 2.1.1.1 of [RFC5480].
            ASN1ObjectIdentifier curveOid = (ASN1ObjectIdentifier) algorithm.getParameters();
            result.rejectIfFalse(SECObjectIdentifiers.secp256r1.equals(curveOid), PUBLIC_KEY_CERT_ALGORITHM, curveOid.getId());
        }
    }

    protected void doTypeSpecificValidation() {
    }

    public ValidationResult getValidationResult() {
        return result;
    }

    public boolean isSuccess() {
        return !result.hasFailures();
    }

    public abstract T getCertificate();

    protected X509Certificate getX509Certificate() {
        return certificate;
    }

    private static X509Certificate parseEncoded(byte[] encoded, ValidationResult result) {
        final X509Certificate certificate = parseX509Certificate(encoded);
        result.rejectIfNull(certificate, CERTIFICATE_PARSED);
        return certificate;
    }

    public static X509Certificate parseX509Certificate(byte[] encoded) {
        try (InputStream input = new ByteArrayInputStream(encoded)) {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(input);
        } catch (final CertificateException | IOException e) {
            return null;
        }
    }


    private void validateSignatureAlgorithm() {
        result.rejectIfFalse(ArrayUtils.contains(ALLOWED_SIGNATURE_ALGORITHM_OIDS, this.certificate.getSigAlgOID()), CERTIFICATE_SIGNATURE_ALGORITHM, this.certificate.getSigAlgOID());
    }

    protected boolean isResourceExtensionPresent() {
        Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
        if (criticalExtensionOIDs == null) {
            return false;
        }

        return criticalExtensionOIDs.contains(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId())
                || criticalExtensionOIDs.contains(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId());
    }

    protected boolean isIpResourceExtensionPresent() {
        if (certificate.getCriticalExtensionOIDs() == null) {
            return false;
        }
        return certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId());
    }

    protected boolean isAsResourceExtensionPresent() {
        if (certificate.getCriticalExtensionOIDs() == null) {
            return false;
        }
        return certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId());
    }

    /**
     * BGP sec Extended Key Usage extension is present and MUST NOT [rfc6547] be marked as critical.
     * @return whether BgpSec extension is present and non-critical.
     */
    protected boolean isBgpSecExtensionPresent() {
        try {
            final List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            return extendedKeyUsage != null && extendedKeyUsage.contains(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER.getId()) && !certificate.getCriticalExtensionOIDs().contains(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER.getId());
        } catch (CertificateParsingException e) {
            return false;
        }
    }

}
