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
