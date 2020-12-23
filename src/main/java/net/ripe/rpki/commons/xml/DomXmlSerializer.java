/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
package net.ripe.rpki.commons.xml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
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
    protected final String xmlns;

    protected DomXmlSerializer(String xmlns) {
        this.xmlns = xmlns;
    }

    protected DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
        final DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
        documentFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        documentFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        documentFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        documentFactory.setNamespaceAware(true);

        final DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();

        return documentBuilder;
    }

    protected String getRequiredAttributeValue(final Element node, final String attr) {
        String value = node.getAttribute(attr);
        if (value == null) {
            throw new DomXmlSerializerException(String.format("attribute '%s' not found", attr));
        }
        return value;
    }

    protected Optional<String> getAttributeValue(final Node node, final String attr) {
        return Optional.ofNullable(node.getAttributes())
                .map(a -> a.getNamedItem(attr))
                .map(item->item.getTextContent());
    }

    protected Optional<Element> getElement(Document doc, String elementName) {
        final Element node = (Element) doc.getElementsByTagNameNS(xmlns, elementName).item(0);
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
