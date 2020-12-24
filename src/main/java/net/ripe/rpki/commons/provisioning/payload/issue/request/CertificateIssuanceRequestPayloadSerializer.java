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
package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;

/**
 * See RFC6492 section 3.3.1 (https://tools.ietf.org/html/rfc6492#section-3.3.1). Example:
 *
 * <code>
 * &lt;?xml version="1.0" encoding="UTF-8"?>
 * &lt;message xmlns="http://www.apnic.net/specs/rescerts/up-down/" version="1" sender="sender" recipient="recipient" type="list"/>
 * </code>
 */
public class CertificateIssuanceRequestPayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateIssuanceRequestPayload> {
    private static final IpResourceSetProvisioningConverter IP_RESOURCE_SET_PROVISIONING_CONVERTER = IpResourceSetProvisioningConverter.INSTANCE;

    public CertificateIssuanceRequestPayloadSerializer() {
        super(PayloadMessageType.issue);
    }

    protected CertificateIssuanceRequestPayload parseXmlPayload(Element message) throws IOException {
        NodeList requestElements = message.getElementsByTagNameNS(xmlns, "request");
        if (requestElements.getLength() != 1) {
            throw new DomXmlSerializerException("missing or multiple request element(s)");
        }
        Element element = (Element) requestElements.item(0);
        CertificateIssuanceRequestElement request = new CertificateIssuanceRequestElement();
        request.setClassName(getRequiredAttributeValue(element, "class_name"));
        request.setAllocatedAsn(getAttributeValue(element, "req_resource_set_as").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        request.setAllocatedIpv4(getAttributeValue(element, "req_resource_set_ipv4").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        request.setAllocatedIpv6(getAttributeValue(element, "req_resource_set_ipv6").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        request.setCertificateRequest(new PKCS10CertificationRequest(Base64.getMimeDecoder().decode(element.getTextContent())));
        return new CertificateIssuanceRequestPayload(request);
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateIssuanceRequestPayload payload) throws IOException {
        CertificateIssuanceRequestElement request = payload.getRequestElement();
        Element node = document.createElementNS(xmlns, "request");
        node.setAttribute("class_name", request.getClassName());
        if (request.getAllocatedAsn() != null) {
            node.setAttribute("req_resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(request.getAllocatedAsn()));
        }
        if (request.getAllocatedIpv4() != null) {
            node.setAttribute("req_resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(request.getAllocatedIpv4()));
        }
        if (request.getAllocatedIpv6() != null) {
            node.setAttribute("req_resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(request.getAllocatedIpv6()));
        }
        node.setTextContent(Base64.getEncoder().encodeToString(request.getCertificateRequest().getEncoded()));
        return Collections.singletonList(node);
    }
}
