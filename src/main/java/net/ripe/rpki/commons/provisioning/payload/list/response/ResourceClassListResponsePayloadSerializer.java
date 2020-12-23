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
package net.ripe.rpki.commons.provisioning.payload.list.response;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.serialization.CertificateUrlListConverter;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import net.ripe.rpki.commons.xml.converters.DateTimeConverter;
import org.joda.time.format.DateTimeFormatter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * See RFC6492 section 3.3.1 (https://tools.ietf.org/html/rfc6492#section-3.3.1). Example:
 *
 * <code>
 * &lt;?xml version="1.0" encoding="UTF-8"?>
 * &lt;message xmlns="http://www.apnic.net/specs/rescerts/up-down/" version="1" sender="sender" recipient="recipient" type="list"/>
 * </code>
 */
public class ResourceClassListResponsePayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<ResourceClassListResponsePayload> {
    private static final DateTimeConverter DATE_TIME_CONVERTER = new DateTimeConverter();
    private static final IpResourceSetProvisioningConverter IP_RESOURCE_SET_PROVISIONING_CONVERTER = IpResourceSetProvisioningConverter.INSTANCE;
    private static final CertificateUrlListConverter CERTIFICATE_URL_LIST_CONVERTER = CertificateUrlListConverter.INSTANCE;

    public ResourceClassListResponsePayloadSerializer() {
        super(PayloadMessageType.list_response);
    }

    protected ResourceClassListResponsePayload parseXmlPayload(Node message) {
        ResourceClassListResponsePayload result = new ResourceClassListResponsePayload(Collections.emptyList());
        return result;
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, ResourceClassListResponsePayload payload) {
        List<Node> result = new ArrayList<>();
        for (ResourceClassListResponseClassElement classElement : payload.getClassElements()) {
            Element node = document.createElementNS(xmlns, "class");
            node.setAttribute("class_name", classElement.getClassName());
            node.setAttribute("cert_url", CERTIFICATE_URL_LIST_CONVERTER.toString(classElement.getCertificateAuthorityUri()));
            node.setAttribute("resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetAsn()));
            node.setAttribute("resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetIpv4()));
            node.setAttribute("resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetIpv6()));
            node.setAttribute("resource_set_notafter", DATE_TIME_CONVERTER.toString(classElement.getValidityNotAfter()));
            node.setAttribute("suggested_sia_head", classElement.getSiaHeadUri());
            classElement.getCertificateElements().stream().map(certificate -> {
                Element elt = document.createElementNS(xmlns, "certificate");
                elt.setAttribute("cert_url", CERTIFICATE_URL_LIST_CONVERTER.toString(certificate.getIssuerCertificatePublicationUris()));
                elt.setAttribute("req_resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(certificate.getAllocatedAsn()));
                elt.setAttribute("req_resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(certificate.getAllocatedIpv4()));
                elt.setAttribute("req_resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(certificate.getAllocatedIpv6()));
                elt.setTextContent(certificate.getCertificate().getBase64String());
                return elt;
            }).forEachOrdered(node::appendChild);
            X509ResourceCertificate issuer = classElement.getIssuer();
            if (issuer != null) {
                Element elt = document.createElementNS(xmlns, "issuer");
                elt.setTextContent(issuer.getBase64String());
                node.appendChild(elt);
            }
            result.add(node);
        }
        return result;
    }
}
