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
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

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

import static net.ripe.rpki.commons.validation.ValidationString.*;

public abstract class X509CertificateParser<T extends AbstractX509CertificateWrapper> {

    private static final String[] ALLOWED_SIGNATURE_ALGORITHM_OIDS = {
            PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
    };

    private static final ECCurve EC_256R1_CURVE = ECNamedCurveTable.getByOID(SECObjectIdentifiers.secp256r1).getCurve();

    protected X509Certificate certificate;

    protected ValidationResult result;

    public void parse(String location, byte[] encoded) {
        parse(ValidationResult.withLocation(location), encoded);
    }

    public void parse(ValidationResult validationResult, byte[] encoded) {
        this.result = validationResult;
        final X509Certificate parsedEncodedCertificate = parseEncoded(encoded, result);
        validateX509Certificate(validationResult, parsedEncodedCertificate);
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

    /**
     * Parse a certificate and return a parsed certificate of the correct (router or resource certificate) type.
     */
    public static X509ResourceCertificate parseCertificate(ValidationResult result, byte[] encoded) {
        final X509Certificate certificate = parseEncoded(encoded, result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        X509CertificateParser<? extends X509ResourceCertificate> parser;
        if (X509CertificateUtil.isRouter(certificate)) {
            parser = new X509RouterCertificateParser();
        } else {
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

    void validateEcPk() {
        final PublicKey publicKey = certificate.getPublicKey();
        result.rejectIfFalse(isEcPk(publicKey), PUBLIC_KEY_CERT_ALGORITHM, publicKey.getAlgorithm());
    }

    void validateEcSecp256r1Pk() {
        // rfc8209#3.3:
        // o  BGPsec Router Certificates MUST include the subjectPublicKeyInfo
        // field described in [RFC8208].
        //
        // PublicKey.getAlgorithm() would return "EC", more validation is required.
        final byte[] enc = certificate.getPublicKey().getEncoded();
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(enc));
        final AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        final ASN1ObjectIdentifier algorithmOid = algorithm.getAlgorithm();

        // https://datatracker.ietf.org/doc/html/rfc8208#section-3.1
        // o  algorithm (an AlgorithmIdentifier type): The id-ecPublicKey OID
        // MUST be used in the algorithm field, as specified in Section 2.1.1
        // of [RFC5480].
        if (result.rejectIfFalse(X9ObjectIdentifiers.id_ecPublicKey.equals(algorithmOid), PUBLIC_KEY_CERT_ALGORITHM, algorithmOid.getId())) {
            // The value for the associated parameters MUST be
            // secp256r1, as specified in Section 2.1.1.1 of [RFC5480].
            ASN1ObjectIdentifier curveOid = (ASN1ObjectIdentifier) algorithm.getParameters();
            if (result.rejectIfFalse(SECObjectIdentifiers.secp256r1.equals(curveOid), PUBLIC_KEY_CERT_ALGORITHM, curveOid.getId())) {
                // rfc8208#3.1:
                //    o  subjectPublicKey: ECPoint MUST be used to encode the certificate's
                //      subjectPublicKey field, as specified in Section 2.2 of [RFC5480].
                //
                // To ensure this, parse the public key on the curve.
                ECPoint ecPoint = null;
                try {
                    ecPoint = EC_256R1_CURVE.decodePoint(subjectPublicKeyInfo.getPublicKeyData().getBytes());
                } catch (IllegalArgumentException | NullPointerException e) {
                    // Passed in public key not valid on curve
                }
                result.rejectIfNull(ecPoint, PUBLIC_KEY_CERT_VALUE);
            }
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

    protected boolean isBgpSecExtensionPresent() {
        try {
            final List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            final boolean present = extendedKeyUsage != null && extendedKeyUsage.contains(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER.getId());
            if (present) {
                result.warnIfTrue(certificate.getCriticalExtensionOIDs().contains(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER.getId()), BGPSEC_EXT_CRITICAL);
            }
            return present;
        } catch (CertificateParsingException e) {
            return false;
        }
    }

}
