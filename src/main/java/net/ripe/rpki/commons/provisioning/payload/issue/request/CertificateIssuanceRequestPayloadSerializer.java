package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayloadXmlSerializer;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;

/**
 * See RFC6492 section 3.4.1 (https://tools.ietf.org/html/rfc6492#section-3.4.1).
 */
public class CertificateIssuanceRequestPayloadSerializer extends AbstractProvisioningPayloadXmlSerializer<CertificateIssuanceRequestPayload> {
    public CertificateIssuanceRequestPayloadSerializer() {
        super(PayloadMessageType.issue);
    }

    @Override
    protected CertificateIssuanceRequestPayload parseXmlPayload(Element message) throws IOException {
        Element requestElement = getSingleChildElement(message, "request");
        CertificateIssuanceRequestElement request = new CertificateIssuanceRequestElement();
        request.setClassName(getRequiredAttributeValue(requestElement, "class_name"));
        request.setAllocatedAsn(getAttributeValue(requestElement, "req_resource_set_as").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        request.setAllocatedIpv4(getAttributeValue(requestElement, "req_resource_set_ipv4").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        request.setAllocatedIpv6(getAttributeValue(requestElement, "req_resource_set_ipv6").map(IP_RESOURCE_SET_PROVISIONING_CONVERTER::fromString).orElse(null));
        request.setCertificateRequest(new PKCS10CertificationRequest(Base64.getMimeDecoder().decode(requestElement.getTextContent())));
        return new CertificateIssuanceRequestPayload(request);
    }

    @Override
    protected Iterable<? extends Node> generateXmlPayload(Document document, CertificateIssuanceRequestPayload payload) throws IOException {
        CertificateIssuanceRequestElement request = payload.getRequestElement();
        Element node = document.createElementNS(xmlns, "request");
        node.setAttribute("class_name", request.getClassName());
        if (request.getAllocatedAsn() != null) {
            node.setAttribute("req_resource_set_as", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(request.getAllocatedAsn()));
        }
        if (request.getAllocatedIpv4() != null) {
            node.setAttribute("req_resource_set_ipv4", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(request.getAllocatedIpv4()));
        }
        if (request.getAllocatedIpv6() != null) {
            node.setAttribute("req_resource_set_ipv6", IP_RESOURCE_SET_PROVISIONING_CONVERTER.toString(request.getAllocatedIpv6()));
        }
        node.setTextContent(Base64.getEncoder().encodeToString(request.getCertificateRequest().getEncoded()));
        return Collections.singletonList(node);
    }
}
