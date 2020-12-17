package net.ripe.rpki.commons.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.Optional;

public abstract class DomXmlSerializer<T> implements XmlSerializer<T> {
    protected DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
        final DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
        documentFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        documentFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        documentFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        documentFactory.setNamespaceAware(true);

        final DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();

        return documentBuilder;
    }

    protected Optional<String> getAttributeValue(final Node node, final String attr) {
        return Optional.ofNullable(node.getAttributes())
                .map(a -> a.getNamedItem(attr))
                .map(item->item.getTextContent());
    }

    protected Optional<Node> getElement(Document doc, String namespace, String elementName) {
        final Node node = doc.getElementsByTagNameNS(namespace, elementName).item(0);
        return Optional.ofNullable(node);
    }

    protected String serialize(final Document document) throws TransformerException {
        final Transformer transformer = TransformerFactory.newInstance().newTransformer();

        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

        final StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(sw));

        return sw.toString();
    }
}
