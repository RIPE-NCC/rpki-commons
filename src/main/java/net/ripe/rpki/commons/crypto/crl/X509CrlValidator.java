/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
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
package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidator;
import org.joda.time.DateTime;

import java.security.SignatureException;

public class X509CrlValidator implements CertificateRepositoryObjectValidator<X509Crl> {

    private AbstractX509CertificateWrapper parent;

    private ValidationOptions options;
    private ValidationResult result;


    public X509CrlValidator(ValidationOptions options, ValidationResult result, AbstractX509CertificateWrapper parent) {
        this.options = options;
        this.result = result;
        this.parent = parent;
    }

    @Override
    public ValidationResult getValidationResult() {
        return result;
    }

    @Override
    public void validate(String location, X509Crl crl) {
        result.setLocation(new ValidationLocation(location));
        checkSignature(crl);
        checkNextUpdate(crl);
    }

    private void checkNextUpdate(X509Crl crl) {
        DateTime now = new DateTime();
        DateTime nextUpdateTime = crl.getNextUpdateTime();
        result.warnIfTrue(now.isAfter(nextUpdateTime), ValidationString.CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime.toString());
    }

    private void checkSignature(X509Crl crl) {
        boolean signatureValid;
        try {
            crl.verify(parent.getPublicKey());
            signatureValid = true;
        } catch (SignatureException e) {
            signatureValid = false;
        }
        result.rejectIfFalse(signatureValid, ValidationString.CRL_SIGNATURE_VALID);
    }
}
