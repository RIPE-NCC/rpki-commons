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
package net.ripe.rpki.commons.ta.serializers;


import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.ta.domain.response.TrustAnchorResponse;
import net.ripe.rpki.commons.util.XML;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.xml.DomXmlSerializer;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import net.ripe.rpki.commons.ta.domain.response.ErrorResponse;
import net.ripe.rpki.commons.ta.domain.response.RevocationResponse;
import net.ripe.rpki.commons.ta.domain.response.SigningResponse;
import net.ripe.rpki.commons.ta.domain.response.TaResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;


public class TrustAnchorResponseSerializer extends DomXmlSerializer<TrustAnchorResponse> {

    private static final Base64.Decoder BASE64_DECODER = Base64.getMimeDecoder();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();

    public static final String CREATION_TIMESTAMP = "requestCreationTimestamp";
    public static final String TRUST_ANCHOR_RESPONSE = "TrustAnchorResponse";
    public static final String X_509_RESOURCE_CERTIFICATE = "X509ResourceCertificate";
    public static final String CRL = "CRL";
    public static final String MANIFEST = "Manifest";
    public static final String ROA = "Roa";
    public static final String ROA_PREFIX = "RoaPrefix";
    public static final String TA_RESPONSES = "taResponses";

    public static final String SIGNING_RESPONSE = "SigningResponse";
    public static final String REVOCATION_RESPONSE = "RevocationResponse";
    public static final String ERROR_RESPONSE = "ErrorResponse";
    public static final String PUBLISHED_OBJECTS = "publishedObjects";
    public static final String URI_ELEMENT = "uri";
    public static final String ENTRY_ELEMENT = "entry";
    public static final String REQUEST_ID = "requestId";
    public static final String RESOURCE_CLASS_NAME = "resourceClassName";
    public static final String ENCODED_PUBLIC_KEY = "encodedPublicKey";
    public static final String MESSAGE = "message";
    public static final String PUBLICATION_URI = "publicationUri";
    public static final String CERTIFICATE = "certificate";
    public static final String ENCODED = "encoded";



    public TrustAnchorResponseSerializer() {
        super("");
    }

    @Override
    public String serialize(TrustAnchorResponse trustAnchorResponse) {
        if (trustAnchorResponse == null) {
            return null;
        }
        try {
            final Document doc = XML.newSecureDocumentBuilder().newDocument();
            final Element responseTrustAnchorResponseElement = addChild(doc, doc, TRUST_ANCHOR_RESPONSE);

            final Long creationTimestamp = trustAnchorResponse.getRequestCreationTimestamp();
            if (creationTimestamp != null) {
                addChild(doc, responseTrustAnchorResponseElement, CREATION_TIMESTAMP)
                    .setTextContent(creationTimestamp.toString());
            }

            final List<TaResponse> taResponses = trustAnchorResponse.getTaResponses();
            if (taResponses != null) {
                final Element taRequestsElement = addChild(doc, responseTrustAnchorResponseElement, TA_RESPONSES);
                for (final TaResponse taResponse : taResponses) {
                    if (taResponse instanceof SigningResponse) {
                        serializeSigningResponse(doc, taRequestsElement, (SigningResponse) taResponse);
                    } else if (taResponse instanceof RevocationResponse) {
                        serializeRevocationResponse(doc, taRequestsElement, (RevocationResponse) taResponse);
                    } else if (taResponse instanceof ErrorResponse) {
                        serializeErrorResponse(doc, taRequestsElement, (ErrorResponse) taResponse);
                    }
                }
            }

            final Map<URI, CertificateRepositoryObject> publishedObjects = trustAnchorResponse.getPublishedObjects();
            if (publishedObjects != null) {
                final Element publishedObjectsElement = addChild(doc, responseTrustAnchorResponseElement, PUBLISHED_OBJECTS);
                for (final Map.Entry<URI, CertificateRepositoryObject> e : publishedObjects.entrySet()) {
                    final Element entryElement = addChild(doc, publishedObjectsElement, ENTRY_ELEMENT);
                    addChild(doc, entryElement, URI_ELEMENT).setTextContent(e.getKey().toString());
                    addEncodedObject(doc, entryElement, e.getValue());
                }
            }
            return serialize(doc);

        } catch (ParserConfigurationException | TransformerException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    private void serializeSigningResponse(Document doc, Element taRequestsElement, SigningResponse taResponse) {
        final Element signingResponseElement = addChild(doc, taRequestsElement, SIGNING_RESPONSE);

        addChild(doc, signingResponseElement, REQUEST_ID).setTextContent(taResponse.getRequestId().toString());
        addChild(doc, signingResponseElement, RESOURCE_CLASS_NAME).setTextContent(taResponse.getResourceClassName());
        addChild(doc, signingResponseElement, PUBLICATION_URI).setTextContent(taResponse.getPublicationUri().toString());

        addChild(doc, addChild(doc, signingResponseElement, CERTIFICATE), ENCODED)
            .setTextContent(BASE64_ENCODER.encodeToString(taResponse.getCertificate().getEncoded()));
    }

    private void serializeRevocationResponse(Document doc, Element taRequestsElement, RevocationResponse taResponse) {
        Element revocationResponseElement = addChild(doc, taRequestsElement, REVOCATION_RESPONSE);

        addChild(doc, revocationResponseElement, REQUEST_ID).setTextContent(taResponse.getRequestId().toString());
        addChild(doc, revocationResponseElement, RESOURCE_CLASS_NAME).setTextContent(taResponse.getResourceClassName());
        addChild(doc, revocationResponseElement, ENCODED_PUBLIC_KEY).setTextContent(taResponse.getEncodedPublicKey());
    }

    private void serializeErrorResponse(Document doc, Element taRequestsElement, ErrorResponse taResponse) {
        Element errorResponseElement = addChild(doc, taRequestsElement, ERROR_RESPONSE);

        addChild(doc, errorResponseElement, REQUEST_ID).setTextContent(taResponse.getRequestId().toString());
        addChild(doc, errorResponseElement, MESSAGE).setTextContent(taResponse.getMessage());
    }

    private void addEncodedObject(Document doc, Element entryElement, CertificateRepositoryObject objects) {
        String tagName;
        if (objects instanceof X509ResourceCertificate) {
            tagName = X_509_RESOURCE_CERTIFICATE;
        } else if (objects instanceof X509Crl) {
            tagName = CRL;
        } else if (objects instanceof ManifestCms) {
            tagName = MANIFEST;
        } else if (objects instanceof RoaCms) {
            tagName = ROA;
        } else {
            throw new RuntimeException("Not implemented serialisation of '" + objects.getClass() + "'");
        }
        final Element objectElement = addChild(doc, entryElement, tagName);
        final String textContent = BASE64_ENCODER.encodeToString(objects.getEncoded());
        addChild(doc, objectElement, ENCODED)
            .setTextContent(textContent);
    }

    @Override
    public TrustAnchorResponse deserialize(String xml) {
        try (final Reader characterStream = new StringReader(xml)) {
            final Document doc = XML.newSecureDocumentBuilder().parse(new InputSource(characterStream));

            final Element taResponseElement = getElement(doc, TRUST_ANCHOR_RESPONSE)
                .orElseThrow(() -> new DomXmlSerializerException(TRUST_ANCHOR_RESPONSE + " element not found"));

            final Element creationTimestampElement = getSingleChildElement(taResponseElement, CREATION_TIMESTAMP);
            final String creationTimeStampText = getElementTextContent(creationTimestampElement);
            final long creationTimeStamp;
            try {
                creationTimeStamp = Long.parseLong(creationTimeStampText);
            } catch (NumberFormatException e) {
                throw new DomXmlSerializerException("creationTimestamp content is not a number: " + creationTimeStampText, e);
            }

            final Element responseListElement = getSingleChildElement(taResponseElement, TA_RESPONSES);
            final List<TaResponse> taResponses = getTaSigningResponses(responseListElement);
            taResponses.addAll(getTaRevocationResponses(responseListElement));
            taResponses.addAll(getTaErrorResponses(responseListElement));

            Map<URI, CertificateRepositoryObject> publishedObjects = getPublishedObjects(taResponseElement);
            return new TrustAnchorResponse(creationTimeStamp, publishedObjects, taResponses);

        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    private Map<URI, CertificateRepositoryObject> getPublishedObjects(Element taResponseElement) {
        Map<URI, CertificateRepositoryObject> publishedObjects = new TreeMap<>();
        final List<Element> entryElements = getChildElements(getSingleChildElement(taResponseElement, PUBLISHED_OBJECTS), ENTRY_ELEMENT);
        for (final Element entryElement : entryElements) {
            final NodeList childNodes = entryElement.getChildNodes();
            String uri = null;
            CertificateRepositoryObject object = null;
            for (int i = 0; i < childNodes.getLength(); ++i) {
                final Node item = childNodes.item(i);
                if (URI_ELEMENT.equals(item.getLocalName())) {
                    uri = getElementTextContent((Element) item);
                }
                if (X_509_RESOURCE_CERTIFICATE.equals(item.getLocalName())) {
                    object = parseObject((Element) item, uri, "tmp.cer");
                } else if (CRL.equals(item.getLocalName())) {
                    object = parseObject((Element) item, uri, "tmp.crl");
                } else if (MANIFEST.equals(item.getLocalName())) {
                    object = parseObject((Element) item, uri, "tmp.mft");
                } else if (ROA.equals(item.getLocalName())) {
                    object = parseObject((Element) item, uri, "tmp.roa");
                }
            }
            if (uri == null) {
                throw new DomXmlSerializerException("<uri> is not found inside of an entry");
            }
            if (object == null) {
                throw new DomXmlSerializerException("Object is not found inside of an entry");
            }
            publishedObjects.put(URI.create(uri), object);
        }
        return publishedObjects;
    }

    private CertificateRepositoryObject parseObject(Element item, String uri, String name) {
        final String parseName = uri != null ? uri : name;
        final byte[] encoded = getBase64(item);
        return CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, ValidationResult.withLocation(parseName));
    }

    private byte[] getBase64(Element e) {
        String encodedContent = getElementTextContent(e);
        return BASE64_DECODER.decode(encodedContent);
    }

    private List<TaResponse> getTaSigningResponses(Element responseListElement) {
        List<TaResponse> responses = new ArrayList<>();
        final List<Element> responseElements = getChildElements(responseListElement, SIGNING_RESPONSE);
        for (final Element signingResponseElement : responseElements) {
            final String requestId = getElementTextContent(getSingleChildElement(signingResponseElement, REQUEST_ID));
            final String resourceClassName = getElementTextContent(getSingleChildElement(signingResponseElement, RESOURCE_CLASS_NAME));
            final String publicationUri = getElementTextContent(getSingleChildElement(signingResponseElement, PUBLICATION_URI));

            final Element encodedCertificateElem = getSingleChildElement(getSingleChildElement(signingResponseElement, CERTIFICATE), ENCODED);
            final byte[] encoded = BASE64_DECODER.decode(getElementTextContent(encodedCertificateElem));
            final X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
            parser.parse("request-" + requestId + ".cer", encoded);
            responses.add(new SigningResponse(
                UUID.fromString(requestId),
                resourceClassName,
                URI.create(publicationUri),
                parser.getCertificate()));
        }
        return responses;
    }

    private Collection<? extends TaResponse> getTaRevocationResponses(Element responseListElement) {
        List<TaResponse> responses = new ArrayList<>();
        final List<Element> responseElements = getChildElements(responseListElement, REVOCATION_RESPONSE);
        for (final Element revocationResponseElement : responseElements) {
            final String requestId = getElementTextContent(getSingleChildElement(revocationResponseElement, REQUEST_ID));
            final String resourceClassName = getElementTextContent(getSingleChildElement(revocationResponseElement, RESOURCE_CLASS_NAME));
            final String encodedPublicKey = getElementTextContent(getSingleChildElement(revocationResponseElement, ENCODED_PUBLIC_KEY));
            responses.add(new RevocationResponse(UUID.fromString(requestId), resourceClassName, encodedPublicKey));
        }
        return responses;
    }

    private Collection<? extends TaResponse> getTaErrorResponses(Element responseListElement) {
        List<TaResponse> responses = new ArrayList<>();
        final List<Element> responseElements = getChildElements(responseListElement, ERROR_RESPONSE);
        for (final Element errorResponseElement : responseElements) {
            final String requestId = getElementTextContent(getSingleChildElement(errorResponseElement, REQUEST_ID));
            final String message = getElementTextContent(getSingleChildElement(errorResponseElement, MESSAGE));
            responses.add(new ErrorResponse(UUID.fromString(requestId), message));
        }
        return responses;
    }

}
