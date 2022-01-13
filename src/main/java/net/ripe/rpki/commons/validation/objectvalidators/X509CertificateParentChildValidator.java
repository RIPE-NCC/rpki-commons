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
package net.ripe.rpki.commons.validation.objectvalidators;

import com.google.common.primitives.Booleans;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.x509.Extension;
import java.time.Instant;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

import static net.ripe.rpki.commons.crypto.JavaSecurityConstants.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;


public abstract class X509CertificateParentChildValidator<T extends AbstractX509CertificateWrapper> {

    private T parent;

    protected T child;

    private X509Crl crl;

    protected final ValidationOptions options;
    protected final ValidationResult result;


    public X509CertificateParentChildValidator(ValidationOptions options, ValidationResult result, T parent, X509Crl crl) {
        this.options = options;
        this.result = result;
        this.parent = parent;
        this.crl = crl;
    }

    public void validate(String location, T certificate) {
        this.child = certificate;
        result.setLocation(new ValidationLocation(location));

        verifySignature();
        verifyValidity();
        verifyCrl();
        verifyIssuer();
        verifyKeyUsage();
        verifyAuthorityKeyIdentifier();
    }

    public ValidationResult getValidationResult() {
        return result;
    }

    protected T getChild() {
        return child;
    }

    private void verifySignature() {
        result.rejectIfFalse(parent.isCa(), ISSUER_IS_CA);

        boolean errorOccurred = false;
        try {
            child.verify(parent.getPublicKey()); // signed with issuer's public key
        } catch (SignatureException | InvalidKeyException e) {
            errorOccurred = true;
        }

        result.rejectIfTrue(errorOccurred, SIGNATURE_VALID);
    }

    private void verifyCrl() {
        if (crl == null) {
            result.rejectIfFalse(child.isRoot(), CRL_REQUIRED);
            return;
        }

        boolean errorOccurred = false;
        try {
            crl.verify(parent.getPublicKey());
        } catch (SignatureException e) {
            errorOccurred = true;
        }

        result.rejectIfTrue(errorOccurred, CRL_SIGNATURE_VALID);
        result.rejectIfTrue(crl.isRevoked(child.getCertificate()), CERT_NOT_REVOKED);
    }

    protected void verifyValidity() {
        final Instant now = options.getClock().instant();
        final Instant notValidBefore = child.getValidityPeriod().getNotValidBefore();
        final Instant notValidAfter = child.getValidityPeriod().getNotValidAfter();
        result.rejectIfTrue(now.isBefore(notValidBefore), NOT_VALID_BEFORE, notValidBefore.toString());
        result.rejectIfTrue(now.isAfter(notValidAfter), NOT_VALID_AFTER, notValidAfter.toString());
    }

    private void verifyIssuer() {
        result.rejectIfFalse(parent.getSubject().equals(child.getIssuer()), PREV_SUBJECT_EQ_ISSUER);
    }

    /**
     * https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.4
     *
     * KeyUsage validation added as warning to be similar to current checks.
     */
    protected void verifyKeyUsage() {
        boolean[] keyUsage = child.getCertificate().getKeyUsage();
        if (!result.warnIfNull(keyUsage, KEY_USAGE_EXT_PRESENT)) {
            return;
        }

        if (!result.rejectIfFalse(child.getCertificate().getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()), KEY_USAGE_EXT_CRITICAL)) {
            return;
        }

        if (child.isCa()) {
            if (result.warnIfFalse(Booleans.countTrue(keyUsage) == 2, KEY_USAGE_INVALID)) {
                result.warnIfFalse(keyUsage[KEYCERTSIGN_INDEX], KEY_CERT_SIGN);
                result.warnIfFalse(keyUsage[CRLSIGN_INDEX], CRL_SIGN);
            }
        } else {
            if (result.warnIfFalse(Booleans.countTrue(keyUsage) == 1, KEY_USAGE_INVALID)) {
                result.warnIfFalse(keyUsage[DIG_SIGN_INDEX], DIG_SIGN);
            }
        }
    }

    private void verifyAuthorityKeyIdentifier() {
        if (child.isRoot()) {
            // self-signed cert does not have AKI
            return;
        }
        byte[] ski = parent.getSubjectKeyIdentifier();
        byte[] aki = child.getAuthorityKeyIdentifier();
        if ((!result.rejectIfNull(ski, SKI_PRESENT)) || (!result.rejectIfNull(aki, AKI_PRESENT))) {
            return;
        }
        result.rejectIfFalse(Arrays.equals(ski, aki), PREV_SKI_EQ_AKI);
    }

}
