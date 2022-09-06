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
import java.util.Base64;
import java.util.Optional;

/**
 * Convert PublisherRequest to/from ISC style XML - https://datatracker.ietf.org/doc/rfc8183/
 */
public class PublisherRequestSerializer extends IdentitySerializer<PublisherRequest> {

    /** RFC4648 encoder */
    private static final Base64.Encoder AUTHORIZATION_TOKEN_ENCODER = Base64.getEncoder();
    /** RFC4648 decoder */
    private static final Base64.Decoder AUTHORIZATION_TOKEN_DECODER = Base64.getDecoder();

    public PublisherRequestSerializer() {
        super();
    }

    @Override
    public PublisherRequest deserialize(String xml) throws IdentitySerializerException {
        try (final StringReader characterStream = new StringReader(xml)) {
            final Document doc = XML.newNamespaceAwareDocumentBuilder().parse(new InputSource(characterStream));

            final Element root = getElement(doc, "publisher_request")
                    .orElseThrow(() -> new IdentitySerializerException("publisher_request element not found"));

            getAttributeValue(root, "version")
                    .filter(v -> "1".equals(v))
                    .orElseThrow(() -> new IdentitySerializerException("version is not supported"));

            final Optional<String> tag = getAttributeValue(root, "tag");

            final String publisherHandle = getRequiredAttributeValue(root, "publisher_handle");

            final ProvisioningIdentityCertificate publisherBpkiTa =
                getBpkiElementContent(doc, "publisher_bpki_ta")
                    .map(bpkiTa -> getProvisioningIdentityCertificate(bpkiTa))
                    .orElseThrow(() -> new IdentitySerializerException("publisher_bpki_ta element not found"));

            final Optional<PublisherRequest.Referral> referral =
                getOptionalSingleChildElement(root, "referral")
                    .map(element -> new PublisherRequest.Referral(
                            getRequiredAttributeValue(element, "referrer"),
                            AUTHORIZATION_TOKEN_DECODER.decode(getElementTextContent(element))
                        )
                    );

            return new PublisherRequest(tag, publisherHandle, publisherBpkiTa, referral);
        } catch (IllegalArgumentException | SAXException | IOException | ParserConfigurationException e) {
            throw new IdentitySerializerException("Failed to parse publisher request", e);
        }
    }


    @Override
    public String serialize(PublisherRequest publisherRequest) throws IdentitySerializerException {
        try {
            final Document document = XML.newNamespaceAwareDocumentBuilder().newDocument();

            final Element requestElement = document.createElementNS(XMLNS, "publisher_request");
            requestElement.setAttribute("version", Integer.toString(publisherRequest.getVersion()));
            publisherRequest.getTag().ifPresent(tag -> requestElement.setAttribute("tag", tag));
            requestElement.setAttribute("publisher_handle", publisherRequest.getPublisherHandle());

            final Element bpkiTaElement = document.createElementNS(XMLNS, "publisher_bpki_ta");
            bpkiTaElement.setTextContent(publisherRequest.getPublisherBpkiTa().getBase64String());

            final Optional<Element> referralElement = publisherRequest.getReferral()
                .map(referral -> {
                    final Element result = document.createElementNS(XMLNS, "referral");
                    result.setAttribute("referrer", referral.getReferrer());
                    result.setTextContent(AUTHORIZATION_TOKEN_ENCODER.encodeToString(referral.getAuthorizationToken()));
                    return result;
                });

            requestElement.appendChild(bpkiTaElement);
            document.appendChild(requestElement);
            referralElement.ifPresent(document::appendChild);

            return serialize(document);
        } catch (ParserConfigurationException | TransformerException e) {
            throw new IdentitySerializerException(e);
        }
    }

}
