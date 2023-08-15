package net.ripe.rpki.commons.provisioning.payload.list.response;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.List;
import java.util.stream.Collectors;

/**
 * See RFC6492 section 3.3.1 (https://tools.ietf.org/html/rfc6492#section-3.3.1). Example:
 *
 * <code>
 * &lt;?xml version="1.0" encoding="UTF-8"?>
 * &lt;message xmlns="http://www.apnic.net/specs/rescerts/up-down/" version="1" sender="sender" recipient="recipient" type="list"/>
 * </code>
 */
public class ResourceClassListResponsePayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<ResourceClassListResponsePayload> {
    public ResourceClassListResponsePayloadSerializer() {
        super(PayloadMessageType.list_response);
    }

    @Override
    protected ResourceClassListResponsePayload parseXmlPayload(Element message) {
        List<ResourceClassListResponseClassElement> classes = getChildElements(message, "class")
                .stream()
                .map(element -> parseClassElementXml(element, ResourceClassListResponseClassElement::new))
                .collect(Collectors.toList());
        return new ResourceClassListResponsePayload(classes);
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, ResourceClassListResponsePayload payload) {
        return payload.getClassElements()
                .stream()
                .map(clazz -> generateClassElementXml(document, clazz))
                .collect(Collectors.toList());
    }

}
