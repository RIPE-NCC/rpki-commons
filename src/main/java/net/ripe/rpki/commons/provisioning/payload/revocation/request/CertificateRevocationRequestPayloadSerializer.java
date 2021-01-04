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
package net.ripe.rpki.commons.provisioning.payload.revocation.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Collections;

/**
 * See RFC6492 section 3.5.1 (https://tools.ietf.org/html/rfc6492#section-3.5.1).
 */
public class CertificateRevocationRequestPayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateRevocationRequestPayload> {
    public CertificateRevocationRequestPayloadSerializer() {
        super(PayloadMessageType.revoke);
    }

    protected CertificateRevocationRequestPayload parseXmlPayload(Element message) {
        Element requestElement = getSingleChildElement(message, "key");
        String className = getRequiredAttributeValue(requestElement, "class_name");
        String ski = getRequiredAttributeValue(requestElement, "ski");
        return new CertificateRevocationRequestPayload(new CertificateRevocationKeyElement(className, ski));
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateRevocationRequestPayload payload) {
        CertificateRevocationKeyElement key = payload.getKeyElement();
        Element keyElement = document.createElementNS(xmlns, "key");
        keyElement.setAttribute("class_name", key.getClassName());
        keyElement.setAttribute("ski", key.getPublicKeyHash());
        return Collections.singletonList(keyElement);
    }
}
