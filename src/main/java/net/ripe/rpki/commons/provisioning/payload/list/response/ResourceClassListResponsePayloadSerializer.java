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
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElement;
import net.ripe.rpki.commons.provisioning.serialization.CertificateUrlListConverter;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import net.ripe.rpki.commons.xml.converters.DateTimeConverter;
import org.joda.time.DateTime;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

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

    protected ResourceClassListResponsePayload parseXmlPayload(Element message) {
        List<ResourceClassListResponseClassElement> classes = new ArrayList<>();
        NodeList classNodes = message.getElementsByTagNameNS(xmlns, "class");
        for (int i = 0; i < classNodes.getLength(); ++i) {
            Element classElement = (Element) classNodes.item(i);
            ResourceClassListResponseClassElement clazz = parseClassElementXml(classElement);
            classes.add(clazz);
        }
        return new ResourceClassListResponsePayload(classes);
    }

    private ResourceClassListResponseClassElement parseClassElementXml(Element element) {
        ResourceClassListResponseClassElement clazz = new ResourceClassListResponseClassElement();
        clazz.setCertUris(CERTIFICATE_URL_LIST_CONVERTER.fromString(getRequiredAttributeValue(element, "cert_url")));
        clazz.setClassName(getRequiredAttributeValue(element, "class_name"));
        clazz.setResourceSetAs(IP_RESOURCE_SET_PROVISIONING_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_as")));
        clazz.setResourceSetIpv4(IP_RESOURCE_SET_PROVISIONING_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_ipv4")));
        clazz.setResourceSetIpv6(IP_RESOURCE_SET_PROVISIONING_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_ipv6")));
        clazz.setValidityNotAfter((DateTime) DATE_TIME_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_notafter")));
        clazz.setSiaHeadUri(getRequiredAttributeValue(element, "suggested_sia_head"));
        NodeList certificateElements = element.getElementsByTagNameNS(xmlns, "certificate");
        for (int j = 0; j < certificateElements.getLength(); ++j) {
            Element certificateElement = (Element) certificateElements.item(j);
            CertificateElement certificate = parseCertificateElementXml(certificateElement);
            clazz.getCertificateElements().add(certificate);
        }
        NodeList issuerElements = element.getElementsByTagNameNS(xmlns, "issuer");
        if (issuerElements.getLength() != 1) {
            throw new DomXmlSerializerException("missing issuer element");
        }
        clazz.setIssuer(parseX509ResourceCertificate(issuerElements.item(0).getTextContent()));
        return clazz;
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, ResourceClassListResponsePayload payload) {
        List<Node> result = new ArrayList<>();
        for (ResourceClassListResponseClassElement classElement : payload.getClassElements()) {
            Element node = document.createElementNS(xmlns, "class");
            node.setAttribute("cert_url", CERTIFICATE_URL_LIST_CONVERTER.toString(classElement.getCertificateAuthorityUri()));
            node.setAttribute("class_name", classElement.getClassName());
            node.setAttribute("resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetAsn()));
            node.setAttribute("resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetIpv4()));
            node.setAttribute("resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetIpv6()));
            node.setAttribute("resource_set_notafter", DATE_TIME_CONVERTER.toString(classElement.getValidityNotAfter()));
            node.setAttribute("suggested_sia_head", classElement.getSiaHeadUri());
            classElement.getCertificateElements().stream().map(certificate -> generateCertificateElementXml(document, certificate)).forEachOrdered(node::appendChild);
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

    private CertificateElement parseCertificateElementXml(Element certificate) {
        CertificateElement result = new CertificateElement();
        result.setIssuerCertificatePublicationLocation(CERTIFICATE_URL_LIST_CONVERTER.fromString(getRequiredAttributeValue(certificate, "cert_url")));
        result.setAllocatedAsn(getAttributeValue(certificate, "req_resource_set_as").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        result.setAllocatedIpv4(getAttributeValue(certificate, "req_resource_set_ipv4").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        result.setAllocatedIpv6(getAttributeValue(certificate, "req_resource_set_ipv6").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        result.setCertificate(parseX509ResourceCertificate(certificate.getTextContent()));
        return result;
    }

    private Element generateCertificateElementXml(Document document, CertificateElement certificate) {
        Element result = document.createElementNS(xmlns, "certificate");
        result.setAttribute("cert_url", CERTIFICATE_URL_LIST_CONVERTER.toString(certificate.getIssuerCertificatePublicationUris()));
        if (certificate.getAllocatedAsn() != null) {
            result.setAttribute("req_resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(certificate.getAllocatedAsn()));
        }
        if (certificate.getAllocatedIpv4() != null) {
            result.setAttribute("req_resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(certificate.getAllocatedIpv4()));
        }
        if (certificate.getAllocatedIpv6() != null) {
            result.setAttribute("req_resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(certificate.getAllocatedIpv6()));
        }
        result.setTextContent(certificate.getCertificate().getBase64String());
        return result;
    }
}
