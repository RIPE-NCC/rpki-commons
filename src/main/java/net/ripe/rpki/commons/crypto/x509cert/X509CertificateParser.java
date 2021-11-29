/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc8209.RouterExtensionEncoder;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

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

    void validateEcPk() {
        final PublicKey publicKey = certificate.getPublicKey();
        result.rejectIfFalse(isEcPk(publicKey), PUBLIC_KEY_CERT_ALGORITHM, publicKey.getAlgorithm());
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
            return extendedKeyUsage != null && extendedKeyUsage.contains(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER.getId());
        } catch (CertificateParsingException e) {
            return false;
        }
    }

}
