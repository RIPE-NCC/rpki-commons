/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.util;

import org.junit.Test;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;


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
        assertThrows(SAXParseException.class, () -> XML.newNamespaceAwareDocumentBuilder().parse(inputStreamFrom(INTERNAL_ENTITY_TEST)));
    }

    @Test
    public void doesNotResolveExternalEntities() {
        assertThrows(SAXParseException.class, () -> XML.newNamespaceAwareDocumentBuilder().parse(inputStreamFrom(EXTERNAL_ENTITY_TEST)));
    }

    @Test
    public void isNamespaceAware() throws ParserConfigurationException {
        assertTrue(XML.newNamespaceAwareDocumentBuilder().isNamespaceAware());
    }

    @Test
    public void isNotNamespaceAware() throws ParserConfigurationException {
        assertFalse(XML.newNonNamespaceAwareDocumentBuilder().isNamespaceAware());
    }
}
