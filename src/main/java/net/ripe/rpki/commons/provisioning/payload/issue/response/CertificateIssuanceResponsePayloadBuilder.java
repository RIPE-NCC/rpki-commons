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
package net.ripe.rpki.commons.provisioning.payload.issue.response;

import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;
import org.apache.commons.lang.Validate;


/**
 * Builder for 'Certificate Issuance Response'<br >
 * See: <a href="http://tools.ietf.org/html/rfc6492#section-3.4.2">http://tools.ietf.org/html/rfc6492#section-3.4.2</a>
 */
public class CertificateIssuanceResponsePayloadBuilder extends AbstractPayloadBuilder<CertificateIssuanceResponsePayload> {

    private CertificateIssuanceResponseClassElement classElement;

    public CertificateIssuanceResponsePayloadBuilder withClassElement(CertificateIssuanceResponseClassElement classElement) {
        this.classElement = classElement;
        return this;
    }

    @Override
    public CertificateIssuanceResponsePayload build() {
        Validate.notNull(classElement, "Need one ClassElement");
        return new CertificateIssuanceResponsePayload(classElement);
    }

}
