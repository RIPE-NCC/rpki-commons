package net.ripe.rpki.commons.provisioning.payload.revocation.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Collections;

/**
 * See RFC6492 section 3.5.1 (https://tools.ietf.org/html/rfc6492#section-3.5.1).
 */
public class CertificateRevocationRequestPayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateRevocationRequestPayload> {
    public CertificateRevocationRequestPayloadSerializer() {
        super(PayloadMessageType.revoke);
    }

    @Override
    protected CertificateRevocationRequestPayload parseXmlPayload(Element message) {
        Element requestElement = getSingleChildElement(message, "key");
        String className = getRequiredAttributeValue(requestElement, "class_name");
        String ski = getRequiredAttributeValue(requestElement, "ski");
        return new CertificateRevocationRequestPayload(new CertificateRevocationKeyElement(className, ski));
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateRevocationRequestPayload payload) {
        CertificateRevocationKeyElement key = payload.getKeyElement();
        Element keyElement = document.createElementNS(xmlns, "key");
        keyElement.setAttribute("class_name", key.getClassName());
        keyElement.setAttribute("ski", key.getPublicKeyHash());
        return Collections.singletonList(keyElement);
    }
}
