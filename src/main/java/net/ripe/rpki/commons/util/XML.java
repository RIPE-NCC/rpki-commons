package net.ripe.rpki.commons.util;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Utilities for working with XML.
 */
public class XML {
    private XML() {}

    /**
     * Create a new document builder that is not vulnerable to XML External Entity injection.
     *
     * @return newly configured DocumentBuilder
     * @throws ParserConfigurationException when feature is not available.
     */
    public static DocumentBuilder newSecureDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // completely disable internal and external doctype declarations
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        factory.setNamespaceAware(true);

        return factory.newDocumentBuilder();
    }
}
