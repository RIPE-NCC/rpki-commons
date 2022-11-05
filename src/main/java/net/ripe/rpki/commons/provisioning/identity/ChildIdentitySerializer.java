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

/**
 * Convert ChildIdentity to/from ISC style XML - https://datatracker.ietf.org/doc/rfc8183/
 */
public class ChildIdentitySerializer extends IdentitySerializer<ChildIdentity> {

    public ChildIdentitySerializer() {
        super();
    }

    @Override
    public ChildIdentity deserialize(String xml) throws IdentitySerializerException {
        try (final StringReader characterStream = new StringReader(xml)) {
            final Document doc = XML.newNamespaceAwareDocumentBuilder().parse(new InputSource(characterStream));

            final Element root = getElement(doc, "child_request")
                    .orElseThrow(() -> new IdentitySerializerException("child_request element not found"));

            final String childHandle = getRequiredAttributeValue(root, "child_handle");

            final String childBpkiTa = getBpkiElementContent(doc, "child_bpki_ta")
                    .orElseThrow(() -> new IdentitySerializerException("child_bpki_ta element not found"));

            final ProvisioningIdentityCertificate provisioningIdentityCertificate = getProvisioningIdentityCertificate(childBpkiTa);

            return new ChildIdentity(childHandle, provisioningIdentityCertificate);

        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new IdentitySerializerException("Fail to parse child request", e);
        }
    }


    @Override
    public String serialize(ChildIdentity childIdentity) throws IdentitySerializerException {

        try {
            final Document document = XML.newNamespaceAwareDocumentBuilder().newDocument();

            final Element childRequestElement = document.createElementNS(XMLNS, "child_request");
            childRequestElement.setAttribute("child_handle", childIdentity.getHandle());
            childRequestElement.setAttribute("version", Integer.toString(childIdentity.getVersion()));

            final Element childBpkiTaElement = document.createElementNS(XMLNS, "child_bpki_ta");
            childBpkiTaElement.setTextContent(childIdentity.getIdentityCertificate().getBase64String());

            childRequestElement.appendChild(childBpkiTaElement);
            document.appendChild(childRequestElement);

            return serialize(document);

        } catch (ParserConfigurationException | TransformerException e) {
            throw new IdentitySerializerException(e);
        }
    }

}
