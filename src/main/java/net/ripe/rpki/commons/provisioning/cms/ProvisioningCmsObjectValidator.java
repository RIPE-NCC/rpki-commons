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
package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlValidator;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCertificateValidator;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

public class ProvisioningCmsObjectValidator {

    private ValidationOptions options;
    private ProvisioningCmsObject cmsObject;
    private ProvisioningIdentityCertificate identityCertificate;

    private ValidationResult validationResult;
    private ProvisioningCmsCertificate cmsCertificate;

    private X509Crl crl;

    public ProvisioningCmsObjectValidator(ValidationOptions options, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate identityCertificate) {
        this.options = options;
        this.cmsObject = cmsObject;
        this.identityCertificate = identityCertificate;
    }

    public void validate(ValidationResult validationResult) {
        this.validationResult = validationResult;

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser(validationResult);
        parser.parseCms("<cms>", cmsObject.getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        cmsCertificate = new ProvisioningCmsCertificate(cmsObject.getCmsCertificate());
        crl = new X509Crl(cmsObject.getCrl());

        validateCrl();
        validateCertificateChain();
    }

    private void validateCrl() {
        X509CrlValidator crlValidator = new X509CrlValidator(new ValidationOptions(), validationResult, identityCertificate);
        crlValidator.validate("<crl>", crl);
    }

    private void validateCertificateChain() {
        validateCmsCertificate();
        validateIdentityCertificate();
    }

    private void validateCmsCertificate() {
        ProvisioningCertificateValidator validator = new ProvisioningCertificateValidator(options, validationResult, identityCertificate, crl);
        validator.validate("<cms-cert>", cmsCertificate);
    }

    private void validateIdentityCertificate() {
        ProvisioningCertificateValidator validator = new ProvisioningCertificateValidator(options, validationResult, identityCertificate, crl);
        validator.validate("<identity-cert>", identityCertificate);
    }
}
