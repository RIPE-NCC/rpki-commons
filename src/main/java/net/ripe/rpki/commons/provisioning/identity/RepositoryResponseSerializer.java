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
import java.util.Optional;

/**
 * Convert RepositoryResponse to/from ISC style XML - https://datatracker.ietf.org/doc/rfc8183/
 */
public class RepositoryResponseSerializer extends IdentitySerializer<RepositoryResponse> {

    public RepositoryResponseSerializer() {
        super();
    }

    @Override
    public RepositoryResponse deserialize(String xml) throws IdentitySerializerException {
        try (final StringReader characterStream = new StringReader(xml)) {
            final Document doc = XML.newNamespaceAwareDocumentBuilder().parse(new InputSource(characterStream));

            final Element root = getElement(doc, "repository_response")
                    .orElseThrow(() -> new IdentitySerializerException("repository_response element not found"));

            getAttributeValue(root, "version")
                .filter(v -> "1".equals(v))
                .orElseThrow(() -> new IdentitySerializerException("version is not supported"));

            final Optional<String> tag = getAttributeValue(root, "tag");

            final URI serviceUri = URI.create(getRequiredAttributeValue(root, "service_uri"));

            final String publisherHandle = getRequiredAttributeValue(root, "publisher_handle");

            final URI siaBase = URI.create(getRequiredAttributeValue(root, "sia_base"));

            final Optional<URI> rrdpNotificationUri = getAttributeValue(root, "rrdp_notification_uri")
                .map(URI::create);

            final ProvisioningIdentityCertificate repositoryBpkiTa =
                getBpkiElementContent(doc, "repository_bpki_ta")
                    .map(bpkiTa -> getProvisioningIdentityCertificate(bpkiTa))
                    .orElseThrow(() -> new IdentitySerializerException("repository_bpki_ta element not found"));

            return new RepositoryResponse(tag, serviceUri, publisherHandle, siaBase, rrdpNotificationUri, repositoryBpkiTa);
        } catch (IllegalArgumentException | SAXException | IOException | ParserConfigurationException e) {
            throw new IdentitySerializerException("Failed to parse repository response", e);
        }
    }


    @Override
    public String serialize(RepositoryResponse repositoryResponse) throws IdentitySerializerException {
        try {
            final Document document = XML.newNamespaceAwareDocumentBuilder().newDocument();

            final Element requestElement = document.createElementNS(XMLNS, "repository_response");
            requestElement.setAttribute("version", Integer.toString(repositoryResponse.getVersion()));
            repositoryResponse.getTag().ifPresent(tag -> requestElement.setAttribute("tag", tag));
            requestElement.setAttribute("service_uri", repositoryResponse.getServiceUri().toASCIIString());
            requestElement.setAttribute("publisher_handle", repositoryResponse.getPublisherHandle());
            requestElement.setAttribute("sia_base", repositoryResponse.getSiaBase().toASCIIString());
            repositoryResponse.getRrdpNotificationUri()
                .ifPresent(uri -> requestElement.setAttribute("rrdp_notification_uri", uri.toASCIIString()));

            final Element bpkiTaElement = document.createElementNS(XMLNS, "repository_bpki_ta");
            bpkiTaElement.setTextContent(repositoryResponse.getRepositoryBpkiTa().getBase64String());

            requestElement.appendChild(bpkiTaElement);
            document.appendChild(requestElement);

            return serialize(document);
        } catch (ParserConfigurationException | TransformerException e) {
            throw new IdentitySerializerException(e);
        }
    }

}
