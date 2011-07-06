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
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;


public class X509ResourceCertificateParentChildValidator extends X509CertificateParentChildValidator <X509ResourceCertificate> implements X509ResourceCertificateValidator {

    private IpResourceSet resources;


    public X509ResourceCertificateParentChildValidator(ValidationResult result, X509ResourceCertificate parent, X509Crl crl, IpResourceSet resources) {
        super(result, parent, crl);
        this.resources = resources;
    }

    @Override
    public void validate(String location, X509ResourceCertificate certificate) {
        super.validate(location, certificate);
        verifyResources();
    }

    private void verifyResources() {
        ValidationResult result = getValidationResult();
        X509ResourceCertificate child = getChild();
        IpResourceSet childResourceSet = child.getResources();

        if (child.isRoot()) {
            // root certificate cannot have inherited resources
            result.isFalse(childResourceSet instanceof InheritedIpResourceSet, RESOURCE_RANGE);
        } else if (childResourceSet instanceof InheritedIpResourceSet) {
            // for other certs inherited resources should always be okay
            return;
        } else {
            // otherwise the child resources cannot exceed the specified resources
            result.isTrue(resources.contains(childResourceSet), RESOURCE_RANGE);
        }
    }

}
