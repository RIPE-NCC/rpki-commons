package net.ripe.rpki.commons.provisioning.identity;


import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.util.XML;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;


/**
 * Convert ParentIdentity to/from ISC style XML
 */
public class ParentIdentitySerializer extends IdentitySerializer<ParentIdentity> {

    public ParentIdentitySerializer() {
        super();
    }

    @Override
    public ParentIdentity deserialize(final String xml) {
        try (final StringReader characterStream = new StringReader(xml)) {
            final Document doc = XML.newNamespaceAwareDocumentBuilder().parse(new InputSource(characterStream));

            final Element root = getElement(doc, "parent_response")
                .orElseThrow(() -> new IdentitySerializerException("parent_response element not found"));

            final String childHandle = getRequiredAttributeValue(root, "child_handle");
            final String parentHandle = getRequiredAttributeValue(root, "parent_handle");
            final String serviceUri = getRequiredAttributeValue(root, "service_uri");

            final String parentBpkiTa = getBpkiElementContent(doc, "parent_bpki_ta")
                    .orElseThrow(() -> new IdentitySerializerException("parent_bpki_ta element not found"));

            final ProvisioningIdentityCertificate provisioningIdentityCertificate = getProvisioningIdentityCertificate(parentBpkiTa);

            return new ParentIdentity(URI.create(serviceUri), parentHandle, childHandle, provisioningIdentityCertificate);

        } catch (SAXException | IOException | ParserConfigurationException e) {
            //TODO: make it a checked exception?
            throw new IdentitySerializerException("Fail to parse parent response", e);
        }
    }

    @Override
    public String serialize(final ParentIdentity parentIdentity) {
        try {
            final Document document = XML.newNamespaceAwareDocumentBuilder().newDocument();

            final Element parentResponseElement = document.createElementNS(XMLNS, "parent_response");
            parentResponseElement.setAttribute("child_handle", parentIdentity.getChildHandle());
            parentResponseElement.setAttribute("parent_handle", parentIdentity.getParentHandle());
            parentResponseElement.setAttribute("service_uri", parentIdentity.getUpDownUrl().toString());
            parentResponseElement.setAttribute("version", Integer.toString(parentIdentity.getVersion()));

            final Element parentBpkiTaElement = document.createElementNS(XMLNS, "parent_bpki_ta");
            parentBpkiTaElement.setTextContent(parentIdentity.getParentIdCertificate().getBase64String());

            parentResponseElement.appendChild(parentBpkiTaElement);
            document.appendChild(parentResponseElement);

           return serialize(document);

        } catch (ParserConfigurationException | TransformerException e) {
            //TODO: make it a checked exception?
            throw new IdentitySerializerException(e);
        }

    }

}
