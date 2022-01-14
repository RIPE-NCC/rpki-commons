package net.ripe.rpki.commons.provisioning.payload.issue.response;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.IOException;
import java.util.Collections;

/**
 * See RFC6492 section 3.4.2 (https://tools.ietf.org/html/rfc6492#section-3.4.2).
 */
public class CertificateIssuanceResponsePayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateIssuanceResponsePayload> {
    public CertificateIssuanceResponsePayloadSerializer() {
        super(PayloadMessageType.issue_response);
    }

    @Override
    protected CertificateIssuanceResponsePayload parseXmlPayload(Element messageElement) throws IOException {
        Element classElement = getSingleChildElement(messageElement, "class");
        // Ensure only a single certificate element is present
        getSingleChildElement(classElement, "certificate");
        CertificateIssuanceResponseClassElement clazz = parseClassElementXml(classElement, CertificateIssuanceResponseClassElement::new);
        return new CertificateIssuanceResponsePayload(clazz);
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateIssuanceResponsePayload payload) throws IOException {
        CertificateIssuanceResponseClassElement clazz = payload.getClassElement();
        Element classElement = generateClassElementXml(document, clazz);
        return Collections.singletonList(classElement);
    }
}
