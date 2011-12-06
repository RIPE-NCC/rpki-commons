/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.validation.objectvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapper;

import org.joda.time.DateTime;


public abstract class X509CertificateParentChildValidator <T extends AbstractX509CertificateWrapper> {

    // http://www.ietf.org/rfc/rfc2459.txt
    private static final int DIG_SIGN_INDEX = 0;
    private static final int KEYCERTSIGN_INDEX = 5;
    private static final int CRLSIGN_INDEX = 6;

    private T parent;

    private T child;

    private X509Crl crl;

    private ValidationResult result;


    public X509CertificateParentChildValidator(ValidationResult result, T parent, X509Crl crl) {
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
        result.isTrue(parent.isCa(), ISSUER_IS_CA);

        boolean errorOccured = false;
        try {
            child.verify(parent.getPublicKey()); // signed with issuer's public key
        } catch (SignatureException e) {
            errorOccured = true;
        } catch (InvalidKeyException e) {
            errorOccured = true;
        }

        result.isFalse(errorOccured, SIGNATURE_VALID);
    }

    private void verifyCrl() {
        if (crl == null) {
            result.isTrue(child.isRoot(), CRL_REQUIRED);
            return;
        }

        boolean errorOccured = false;
        try {
            crl.verify(parent.getPublicKey());
        } catch (SignatureException e) {
            errorOccured = true;
        }

        result.isFalse(errorOccured, CRL_SIGNATURE_VALID);
        result.isFalse(crl.isRevoked(child.getCertificate()), CERT_NOT_REVOKED);
    }

    private void verifyValidity() {
        DateTime now = new DateTime();

        result.isFalse(now.isBefore(child.getValidityPeriod().getNotValidBefore()), NOT_VALID_BEFORE, child.getValidityPeriod().getNotValidBefore());
        result.isFalse(now.isAfter(child.getValidityPeriod().getNotValidAfter()), NOT_VALID_AFTER, child.getValidityPeriod().getNotValidAfter());
    }

    private void verifyIssuer() {
        result.isTrue(parent.getSubject().equals(child.getIssuer()), PREV_SUBJECT_EQ_ISSUER);
    }

    protected void verifyKeyUsage() {
        boolean[] keyUsage = child.getCertificate().getKeyUsage();
        if (!result.notNull(keyUsage, KEY_USAGE_EXT_PRESENT)) {
            return;
        }

        if (child.isCa()) {
            result.isTrue(keyUsage[KEYCERTSIGN_INDEX], KEY_CERT_SIGN);
            result.isTrue(keyUsage[CRLSIGN_INDEX], CRL_SIGN);
        } else {
            result.isTrue(keyUsage[DIG_SIGN_INDEX], DIG_SIGN);
        }
    }

    private void verifyAuthorityKeyIdentifier() {
        if (child.isRoot()) {
            // self-signed cert does not have AKI
            return;
        }
        byte[] ski = parent.getSubjectKeyIdentifier();
        byte[] aki = child.getAuthorityKeyIdentifier();
        if ((!result.notNull(ski, SKI_PRESENT)) || (!result.notNull(aki, AKI_PRESENT))) {
            return;
        }
        result.isTrue(Arrays.equals(ski, aki), PREV_SKI_EQ_AKI);
    }

}
