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
package net.ripe.rpki.commons.provisioning.payload.list.request;

import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
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

import static net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload.SUPPORTED_VERSION;

/**
 * See RFC6492 section 3.3.1 (https://tools.ietf.org/html/rfc6492#section-3.3.1). Example:
 *
 * <code>
 * &lt;?xml version="1.0" encoding="UTF-8"?>
 * &lt;message xmlns="http://www.apnic.net/specs/rescerts/up-down/" version="1" sender="sender" recipient="recipient" type="list"/>
 * </code>
 */
public class ResourceClassListQueryPayloadSerializer extends DomXmlSerializer<ResourceClassListQueryPayload> {
    private static final String XMLNS = "http://www.apnic.net/specs/rescerts/up-down/";

    @Override
    public String serialize(ResourceClassListQueryPayload object) {
        try {
            final Document document = getDocumentBuilder().newDocument();

            final Element message = document.createElementNS(XMLNS, "message");
            message.setAttribute("version", String.valueOf(object.getVersion()));
            message.setAttribute("sender", object.getSender());
            message.setAttribute("recipient", object.getRecipient());
            message.setAttribute("type", String.valueOf(object.getType()));
            document.appendChild(message);

            return serialize(document);
        } catch (ParserConfigurationException | TransformerException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    @Override
    public ResourceClassListQueryPayload deserialize(String xml) {
        try (final Reader characterStream = new StringReader(xml)) {
            Document doc = getDocumentBuilder().parse(new InputSource(characterStream));

            Node message = getElement(doc, XMLNS, "message")
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
            if (type != PayloadMessageType.list) {
                throw new DomXmlSerializerException("type attribute is not 'list'");
            }

            ResourceClassListQueryPayload result = new ResourceClassListQueryPayload(version, type);
            result.setSender(sender);
            result.setRecipient(recipient);
            return result;
        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new DomXmlSerializerException(e);
        }
    }
}
