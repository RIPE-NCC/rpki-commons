package net.ripe.rpki.commons.util;

import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;


public class XMLTest {
    public final static String INTERNAL_ENTITY_TEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [<!ENTITY toreplace \"3\"> ]>\n" +
            "<stockCheck>\n" +
            "    <productId>&toreplace;</productId>\n" +
            "    <storeId>1</storeId>\n" +
            "</stockCheck>";
    public final static String EXTERNAL_ENTITY_TEST = "<!--?xml version=\"1.0\" ?-->\n" +
            "<!DOCTYPE foo [<!ENTITY example SYSTEM \"/etc/passwd\"> ]>\n" +
            "<data>&example;</data>";

    private static InputStream inputStreamFrom(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void doesNotResolveInternalEntities() throws ParserConfigurationException, IOException, SAXException {
        assertThrows(SAXParseException.class, () -> XML.newSecureDocumentBuilder().parse(inputStreamFrom(INTERNAL_ENTITY_TEST)));
    }

    @Test
    public void doesNotResolveExternalEntities() {
        assertThrows(SAXParseException.class, () -> XML.newSecureDocumentBuilder().parse(inputStreamFrom(EXTERNAL_ENTITY_TEST)));
    }
}
