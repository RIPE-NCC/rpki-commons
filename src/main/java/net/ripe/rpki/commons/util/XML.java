package net.ripe.rpki.commons.util;

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
    private static DocumentBuilder newDocumentBuilder(boolean namespaceAware) throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // following internal documentation and https://rules.sonarsource.com/java/RSPEC-2755
        // completely disable internal and external doctype declarations
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        factory.setNamespaceAware(namespaceAware);

        return factory.newDocumentBuilder();
    }

    /**
     * @return a namespace aware DocumentBuilder
     */
    public static DocumentBuilder newNamespaceAwareDocumentBuilder() throws ParserConfigurationException {
        return newDocumentBuilder(true);
    }

    /**
     * @return a non-namespace aware DocumentBuilder (required to parse IANA XML)
     */
    public static DocumentBuilder newNonNamespaceAwareDocumentBuilder() throws ParserConfigurationException {
        return newDocumentBuilder(false);
    }
}
