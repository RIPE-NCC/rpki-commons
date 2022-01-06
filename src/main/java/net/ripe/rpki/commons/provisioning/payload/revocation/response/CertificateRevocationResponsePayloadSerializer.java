package net.ripe.rpki.commons.provisioning.payload.revocation.response;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Collections;

/**
 * See RFC6492 section 3.5.2 (https://tools.ietf.org/html/rfc6492#section-3.5.2).
 */
public class CertificateRevocationResponsePayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateRevocationResponsePayload> {
    public CertificateRevocationResponsePayloadSerializer() {
        super(PayloadMessageType.revoke_response);
    }

    @Override
    protected CertificateRevocationResponsePayload parseXmlPayload(Element message) {
        Element requestElement = getSingleChildElement(message, "key");
        String className = getRequiredAttributeValue(requestElement, "class_name");
        String ski = getRequiredAttributeValue(requestElement, "ski");
        return new CertificateRevocationResponsePayload(new CertificateRevocationKeyElement(className, ski));
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateRevocationResponsePayload payload) {
        CertificateRevocationKeyElement key = payload.getKeyElement();
        Element keyElement = document.createElementNS(xmlns, "key");
        keyElement.setAttribute("class_name", key.getClassName());
        keyElement.setAttribute("ski", key.getPublicKeyHash());
        return Collections.singletonList(keyElement);
    }
}
