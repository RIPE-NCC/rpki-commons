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
package net.ripe.rpki.commons.crypto;

import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import java.net.URI;

import static net.ripe.rpki.commons.validation.ValidationString.VALIDATOR_REPO_EXECUTION;

public class UnknownCertificateRepositoryObject implements CertificateRepositoryObject {

    private static final long serialVersionUID = 1L;

    private final byte[] encoded;

    public UnknownCertificateRepositoryObject(byte[] encoded) {
        this.encoded = encoded;
    }

    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        result.warn(VALIDATOR_REPO_EXECUTION, "This object type is not supported for " + location);
    }

    @Override
    public void validate(String location,
                         CertificateRepositoryObjectValidationContext context,
                         X509Crl crl,
                         URI crlUri,
                         ValidationOptions options,
                         ValidationResult result) {
        result.warn(VALIDATOR_REPO_EXECUTION, "This object type is not supported for " + location);
    }

    @Override
    public boolean isPastValidityTime() {
        throw new UnsupportedOperationException("Unknown object type");
    }

    @Override
    public boolean isRevoked() {
        return false;
    }

    public URI getCrlUri() {
        throw new UnsupportedOperationException("Unknown object type");
    }

    public URI getParentCertificateUri() {
        throw new UnsupportedOperationException("Unknown object type");
    }

    public byte[] getEncoded() {
        return encoded;
    }
}
