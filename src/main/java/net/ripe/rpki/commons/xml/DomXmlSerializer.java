package net.ripe.rpki.commons.xml;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public abstract class DomXmlSerializer<T> implements XmlSerializer<T> {
    protected final String xmlns;

    protected DomXmlSerializer(String xmlns) {
        this.xmlns = xmlns;
    }

    protected String getRequiredAttributeValue(final Element node, final String attr) {
        return getAttributeValue(node, attr).<DomXmlSerializerException>orElseThrow(() -> {
            throw new DomXmlSerializerException(String.format("attribute '%s' not found", attr));
        });
    }

    protected Optional<String> getAttributeValue(final Element node, final String attr) {
        return node.hasAttribute(attr) ? Optional.of(node.getAttribute(attr)) : Optional.empty();
    }

    protected Optional<Element> getElement(Document doc, String elementName) {
        final Element node = (Element) doc.getElementsByTagNameNS(xmlns, elementName).item(0);
        return Optional.ofNullable(node);
    }

    protected Element getSingleChildElement(Element parent, String tagName) {
        NodeList nodeList = parent.getElementsByTagNameNS(xmlns, tagName);
        if (nodeList.getLength() != 1) {
            throw new DomXmlSerializerException(String.format(nodeList.getLength() == 0 ? "single element '%s' not found" : "multiple elements '%s' present, single element expected", tagName));
        }
        return (Element) nodeList.item(0);
    }

    protected Optional<Element> getOptionalSingleChildElement(Element parent, String tagName) {
        NodeList nodeList = parent.getElementsByTagNameNS(xmlns, tagName);
        if(nodeList.getLength() == 0){
            return Optional.empty();
        }
        return Optional.of(getSingleChildElement(parent, tagName));
    }

    protected List<Element> getChildElements(Element parent, String tagName) {
        NodeList nodeList = parent.getElementsByTagNameNS(xmlns, tagName);
        ArrayList<Element> result = new ArrayList<>(nodeList.getLength());
        for (int i = 0; i < nodeList.getLength(); ++i) {
            result.add((Element) nodeList.item(i));
        }
        return result;
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

    public Element addChild(Document doc, Node parent, String childName) {
        final Element child = doc.createElement(childName);
        parent.appendChild(child);
        return child;
    }

    protected String getElementTextContent(Element element) {
        try {
            return element.getTextContent();
        } catch (DOMException e) {
            throw new DomXmlSerializerException("Error reading " + element.getLocalName() + " content", e);
        }
    }
}
