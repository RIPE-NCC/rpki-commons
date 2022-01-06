package net.ripe.rpki.commons.provisioning.payload.list.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Collections;

/**
 * See RFC6492 section 3.3.1 (https://tools.ietf.org/html/rfc6492#section-3.3.1). Example:
 *
 * <code>
 * &lt;?xml version="1.0" encoding="UTF-8"?>
 * &lt;message xmlns="http://www.apnic.net/specs/rescerts/up-down/" version="1" sender="sender" recipient="recipient" type="list"/>
 * </code>
 */
public class ResourceClassListQueryPayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<ResourceClassListQueryPayload> {
    public ResourceClassListQueryPayloadSerializer() {
        super(PayloadMessageType.list);
    }

    @Override
    protected ResourceClassListQueryPayload parseXmlPayload(Element message) {
        return new ResourceClassListQueryPayload();
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, ResourceClassListQueryPayload payload) {
        return Collections.emptyList();
    }
}
