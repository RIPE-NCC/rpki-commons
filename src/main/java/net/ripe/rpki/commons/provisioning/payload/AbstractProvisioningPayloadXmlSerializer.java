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
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.xml.DomXmlSerializer;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
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

import static net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload.SUPPORTED_VERSION;

public abstract class AbstractProvisioningPayloadXmlSerializer<T extends AbstractProvisioningPayload> extends DomXmlSerializer<T> {
    private static final String XMLNS = "http://www.apnic.net/specs/rescerts/up-down/";

    /**
     * We use the MIME decoder (RFC 2045) here to make the ProcessApnicPdusTest#apnic_pdu_2011_08_15_1_has_errors test
     * work. The standard requires a stricter base-64 encoding from RFC 4648 which we use for encoding.
     */
    private static final Base64.Decoder BASE64_DECODER = Base64.getMimeDecoder();

    private final PayloadMessageType type;

    protected AbstractProvisioningPayloadXmlSerializer(PayloadMessageType type) {
        super(XMLNS);
        this.type = type;
    }

    protected abstract T parseXmlPayload(Element message);

    protected abstract Iterable<? extends Node> generateXmlPayload(Document document, T payload);

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
            Document doc = getDocumentBuilder().parse(new InputSource(characterStream));

            Element message = getElement(doc, "message")
                    .orElseThrow(() -> new DomXmlSerializerException("message element not found"));

            String versionString = getAttributeValue(message, "version")
                    .orElseThrow(() -> new DomXmlSerializerException("version attribute not found"));
            Integer version;
            try {
                version = Integer.parseUnsignedInt(versionString);
            } catch (NumberFormatException e) {
                throw new DomXmlSerializerException("version attribute is not a number: " + versionString, e);
            }
            if (!SUPPORTED_VERSION.equals(version)) {
                throw new DomXmlSerializerException("version attribute is not '1': " + version);
            }

            String sender = getAttributeValue(message, "sender")
                    .orElseThrow(() -> new DomXmlSerializerException("sender attribute not found"));

            String recipient = getAttributeValue(message, "recipient")
                    .orElseThrow(() -> new DomXmlSerializerException("recipient attribute not found"));

            String typeString = getAttributeValue(message, "type")
                    .orElseThrow(() -> new DomXmlSerializerException("type attribute not found"));
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
            final Document document = getDocumentBuilder().newDocument();

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
        } catch (ParserConfigurationException | TransformerException e) {
            throw new DomXmlSerializerException(e);
        }
    }
}
