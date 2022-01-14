package net.ripe.rpki.commons.provisioning.payload.error;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.List;

/**
 * See RFC6492 section 3.6 (https://tools.ietf.org/html/rfc6492#section-3.6).
 */
public class RequestNotPerformedResponsePayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<RequestNotPerformedResponsePayload> {
    public RequestNotPerformedResponsePayloadSerializer() {
        super(PayloadMessageType.error_response);
    }

    @Override
    protected RequestNotPerformedResponsePayload parseXmlPayload(Element messageElement) {
        Element statusElement = getSingleChildElement(messageElement, "status");
        String description = getChildElements(messageElement, "description").stream().findFirst().map(Element::getTextContent).orElse(null);
        try {
            final int errorCode = Integer.parseInt(statusElement.getTextContent().trim());
            return new RequestNotPerformedResponsePayload(NotPerformedError.getError(errorCode), description);
        } catch (NumberFormatException e) {
            throw new DomXmlSerializerException("Illegal status code", e);
        }
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, RequestNotPerformedResponsePayload payload) {
        List<Element> result = new ArrayList<>();
        Element statusElement = document.createElementNS(xmlns, "status");
        statusElement.setTextContent(String.valueOf(payload.getStatus().getErrorCode()));
        result.add(statusElement);
        if (payload.getDescription() != null) {
            Element descriptionElement = document.createElementNS(xmlns, "description");
            descriptionElement.setAttribute("xml:lang", "en-US");
            descriptionElement.setTextContent(payload.getDescription());
            result.add(descriptionElement);
        }
        return result;
    }
}
