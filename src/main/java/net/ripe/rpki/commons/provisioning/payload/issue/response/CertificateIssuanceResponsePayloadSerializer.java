/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.IOException;
import java.util.Collections;

/**
 * See RFC6492 section 3.4.2 (https://tools.ietf.org/html/rfc6492#section-3.4.2).
 */
public class CertificateIssuanceResponsePayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateIssuanceResponsePayload> {
    public CertificateIssuanceResponsePayloadSerializer() {
        super(PayloadMessageType.issue_response);
    }

    protected CertificateIssuanceResponsePayload parseXmlPayload(Element messageElement) throws IOException {
        Element classElement = getSingleChildElement(messageElement, "class");
        // Ensure only a single certificate element is present
        getSingleChildElement(classElement, "certificate");
        CertificateIssuanceResponseClassElement clazz = parseClassElementXml(classElement, CertificateIssuanceResponseClassElement::new);
        return new CertificateIssuanceResponsePayload(clazz);
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateIssuanceResponsePayload payload) throws IOException {
        CertificateIssuanceResponseClassElement clazz = payload.getClassElement();
        Element classElement = generateClassElementXml(document, clazz);
        return Collections.singletonList(classElement);
    }
}
