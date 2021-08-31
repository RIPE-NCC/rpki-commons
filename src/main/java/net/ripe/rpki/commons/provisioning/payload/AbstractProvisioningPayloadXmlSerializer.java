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
package net.ripe.rpki.commons.provisioning.payload;

import net.ripe.rpki.commons.crypto.x509cert.X509GenericCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElement;
import net.ripe.rpki.commons.provisioning.payload.common.GenericClassElement;
import net.ripe.rpki.commons.provisioning.serialization.CertificateUrlListConverter;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import net.ripe.rpki.commons.util.XML;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.xml.DomXmlSerializer;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import net.ripe.rpki.commons.xml.converters.DateTimeConverter;
import org.joda.time.DateTime;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload.SUPPORTED_VERSION;

public abstract class AbstractProvisioningPayloadXmlSerializer<T extends AbstractProvisioningPayload> extends DomXmlSerializer<T> {
    private static final String XMLNS = "http://www.apnic.net/specs/rescerts/up-down/";

    /**
     * We use the MIME decoder (RFC 2045) here to make the ProcessApnicPdusTest#apnic_pdu_2011_08_15_1_has_errors test
     * work. The standard requires a stricter base-64 encoding from RFC 4648 which we use for encoding.
     */
    private static final Base64.Decoder BASE64_DECODER = Base64.getMimeDecoder();

    protected static final IpResourceSetProvisioningConverter IP_RESOURCE_SET_PROVISIONING_CONVERTER = IpResourceSetProvisioningConverter.INSTANCE;
    protected static final CertificateUrlListConverter CERTIFICATE_URL_LIST_CONVERTER = CertificateUrlListConverter.INSTANCE;
    protected static final DateTimeConverter DATE_TIME_CONVERTER = new DateTimeConverter();

    private final PayloadMessageType type;

    protected AbstractProvisioningPayloadXmlSerializer(PayloadMessageType type) {
        super(XMLNS);
        this.type = type;
    }

    protected abstract T parseXmlPayload(Element message) throws IOException;

    protected abstract Iterable<? extends Node> generateXmlPayload(Document document, T payload) throws IOException;

    protected X509ResourceCertificate parseX509ResourceCertificate(String base64) {
        ValidationResult result = ValidationResult.withLocation("certificate.cer").withoutStoringPassingChecks();
        X509GenericCertificate certificate = X509ResourceCertificateParser.parseCertificate(result, BASE64_DECODER.decode(base64.trim()));
        if (result.hasFailureForCurrentLocation()) {
            throw new DomXmlSerializerException("resource certificate validation failed: " + result);
        } else if (certificate instanceof X509ResourceCertificate) {
            return (X509ResourceCertificate) certificate;
        } else {
            throw new DomXmlSerializerException("certificate is not a resource certificate: " + certificate);
        }
    }

    @Override
    public T deserialize(String xml) {
        try (final Reader characterStream = new StringReader(xml)) {
            Document doc = XML.newNamespaceAwareDocumentBuilder().parse(new InputSource(characterStream));

            Element message = getElement(doc, "message")
                    .orElseThrow(() -> new DomXmlSerializerException("message element not found"));

            String versionString = getRequiredAttributeValue(message, "version");
            Integer version;
            try {
                version = Integer.parseUnsignedInt(versionString);
            } catch (NumberFormatException e) {
                throw new DomXmlSerializerException("version attribute is not a number: " + versionString, e);
            }
            if (!SUPPORTED_VERSION.equals(version)) {
                throw new DomXmlSerializerException("version attribute is not '1': " + version);
            }

            String sender = getRequiredAttributeValue(message, "sender");
            String recipient = getRequiredAttributeValue(message, "recipient");
            String typeString = getRequiredAttributeValue(message, "type");
            PayloadMessageType type;
            try {
                type = PayloadMessageType.valueOf(typeString);
            } catch (IllegalArgumentException e) {
                throw new DomXmlSerializerException("type is not supported: " + typeString, e);
            }
            if (type != this.type) {
                throw new DomXmlSerializerException(String.format("type attribute is not '%s'", this.type.toString()));
            }

            T result = parseXmlPayload(message);
            result.setSender(sender);
            result.setRecipient(recipient);
            return result;
        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    @Override
    public String serialize(T payload) {
        try {
            final Document document = XML.newNamespaceAwareDocumentBuilder().newDocument();

            final Element message = document.createElementNS(xmlns, "message");
            message.setAttribute("version", String.valueOf(payload.getVersion()));
            message.setAttribute("sender", payload.getSender());
            message.setAttribute("recipient", payload.getRecipient());
            message.setAttribute("type", String.valueOf(payload.getType()));

            for (Node node : generateXmlPayload(document, payload)) {
                message.appendChild(node);
            }

            document.appendChild(message);

            return serialize(document);
        } catch (ParserConfigurationException | TransformerException | IOException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    protected CertificateElement parseCertificateElementXml(Element certificate) {
        CertificateElement result = new CertificateElement();
        result.setIssuerCertificatePublicationLocation(CERTIFICATE_URL_LIST_CONVERTER.fromString(getRequiredAttributeValue(certificate, "cert_url")));
        result.setAllocatedAsn(getAttributeValue(certificate, "req_resource_set_as").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        result.setAllocatedIpv4(getAttributeValue(certificate, "req_resource_set_ipv4").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        result.setAllocatedIpv6(getAttributeValue(certificate, "req_resource_set_ipv6").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        result.setCertificate(parseX509ResourceCertificate(certificate.getTextContent()));
        return result;
    }

    protected Element generateCertificateElementXml(Document document, CertificateElement certificate) {
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

    protected <U extends GenericClassElement> U parseClassElementXml(Element element, Supplier<U> clazzSupplier) {
        U clazz = clazzSupplier.get();
        clazz.setCertUris(CERTIFICATE_URL_LIST_CONVERTER.fromString(getRequiredAttributeValue(element, "cert_url")));
        clazz.setClassName(getRequiredAttributeValue(element, "class_name"));
        clazz.setResourceSetAs(IP_RESOURCE_SET_PROVISIONING_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_as")));
        clazz.setResourceSetIpv4(IP_RESOURCE_SET_PROVISIONING_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_ipv4")));
        clazz.setResourceSetIpv6(IP_RESOURCE_SET_PROVISIONING_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_ipv6")));
        clazz.setValidityNotAfter((DateTime) DATE_TIME_CONVERTER.fromString(getRequiredAttributeValue(element, "resource_set_notafter")));
        clazz.setSiaHeadUri(getAttributeValue(element, "suggested_sia_head").orElse(null));
        List<CertificateElement> certificateElements = getChildElements(element, "certificate")
                .stream()
                .map(this::parseCertificateElementXml)
                .collect(Collectors.toList());
        clazz.setCertificateElements(certificateElements);
        Element issuerElement = getSingleChildElement(element, "issuer");
        clazz.setIssuer(parseX509ResourceCertificate(issuerElement.getTextContent()));
        return clazz;
    }

    protected Element generateClassElementXml(Document document, GenericClassElement classElement) {
        Element node = document.createElementNS(xmlns, "class");
        node.setAttribute("cert_url", CERTIFICATE_URL_LIST_CONVERTER.toString(classElement.getCertificateAuthorityUri()));
        node.setAttribute("class_name", classElement.getClassName());
        node.setAttribute("resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetAsn()));
        node.setAttribute("resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetIpv4()));
        node.setAttribute("resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(classElement.getResourceSetIpv6()));
        node.setAttribute("resource_set_notafter", DATE_TIME_CONVERTER.toString(classElement.getValidityNotAfter()));
        if (classElement.getSiaHeadUri() != null) {
            node.setAttribute("suggested_sia_head", classElement.getSiaHeadUri());
        }
        classElement.getCertificateElements().stream().map(certificate -> generateCertificateElementXml(document, certificate)).forEachOrdered(node::appendChild);
        X509ResourceCertificate issuer = classElement.getIssuer();
        if (issuer != null) {
            Element elt = document.createElementNS(xmlns, "issuer");
            elt.setTextContent(issuer.getBase64String());
            node.appendChild(elt);
        }
        return node;
    }
}
