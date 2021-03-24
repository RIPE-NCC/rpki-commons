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

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.xml.DomXmlSerializer;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import net.ripe.rpki.commons.ta.domain.request.ResourceCertificateRequestData;
import net.ripe.rpki.commons.ta.domain.request.RevocationRequest;
import net.ripe.rpki.commons.ta.domain.request.SigningRequest;
import net.ripe.rpki.commons.ta.domain.request.TaRequest;
import net.ripe.rpki.commons.ta.domain.request.TrustAnchorRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class TrustAnchorRequestSerializer extends DomXmlSerializer<TrustAnchorRequest> {

    private static final Base64.Decoder BASE64_DECODER = Base64.getMimeDecoder();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getMimeEncoder();
    public static final String REQUESTS_TRUST_ANCHOR_REQUEST = "requests.TrustAnchorRequest";
    public static final String CREATION_TIMESTAMP = "creationTimestamp";
    public static final String TA_CERTIFICATE_PUBLICATION_URI = "taCertificatePublicationUri";
    public static final String TA_REQUESTS = "taRequests";
    public static final String SIA_DESCRIPTORS = "siaDescriptors";
    public static final String X_509_CERTIFICATE_INFORMATION_ACCESS_DESCRIPTOR = "X509CertificateInformationAccessDescriptor";
    public static final String METHOD = "method";
    public static final String LOCATION = "location";
    public static final String REQUESTS_REVOCATION_REQUEST = "requests.RevocationRequest";
    public static final String RESOURCE_CLASS_NAME = "resourceClassName";
    public static final String ENCODED_REVOCATION_PUBLIC_KEY = "encodedPublicKey";
    public static final String REQUEST_ID = "requestId";
    public static final String REQUESTS_SIGNING_REQUEST = "requests.SigningRequest";
    public static final String RESOURCE_CERTIFICATE_REQUEST = "resourceCertificateRequest";
    public static final String SUBJECT_DN = "subjectDN";
    public static final String ENCODED_SIGNING_SUBJECT_PUBLIC_KEY = "encodedSubjectPublicKey";
    public static final String SUBJECT_INFORMATION_ACCESS = "subjectInformationAccess";

    public TrustAnchorRequestSerializer() {
        super("");
    }

    @Override
    public String serialize(TrustAnchorRequest trustAnchorRequest) {
        if (trustAnchorRequest == null) {
            return null;
        }

        try {
            final Document doc = getDocumentBuilder().newDocument();
            final Element requestsTrustAnchorRequestElement = addChild(doc, doc, REQUESTS_TRUST_ANCHOR_REQUEST);

            final URI taCertificatePublicationUri = trustAnchorRequest.getTaCertificatePublicationUri();
            if (taCertificatePublicationUri != null) {
                addChild(doc, requestsTrustAnchorRequestElement, TA_CERTIFICATE_PUBLICATION_URI)
                    .setTextContent(taCertificatePublicationUri.toString());
            }

            final Long creationTimestamp = trustAnchorRequest.getCreationTimestamp();
            if (creationTimestamp != null) {
                addChild(doc, requestsTrustAnchorRequestElement, CREATION_TIMESTAMP)
                    .setTextContent(creationTimestamp.toString());
            }

            final List<TaRequest> taRequests = trustAnchorRequest.getTaRequests();
            if (taRequests != null) {
                final Element taRequestsElement = addChild(doc, requestsTrustAnchorRequestElement, TA_REQUESTS);
                for (TaRequest taRequest : taRequests) {
                    if (taRequest instanceof SigningRequest) {
                        final Element signingRequestElement = addChild(doc, taRequestsElement, REQUESTS_SIGNING_REQUEST);
                        serializeSigningRequest(doc, signingRequestElement, (SigningRequest) taRequest);
                    } else if (taRequest instanceof RevocationRequest) {
                        final Element revocationRequestElement = addChild(doc, taRequestsElement, REQUESTS_REVOCATION_REQUEST);
                        serializeRevocationRequest(doc, revocationRequestElement, (RevocationRequest) taRequest);
                    }
                }
            }

            final X509CertificateInformationAccessDescriptor[] descriptors = trustAnchorRequest.getSiaDescriptors();
            if (descriptors != null) {
                final Element siaDescriptors = addChild(doc, requestsTrustAnchorRequestElement, SIA_DESCRIPTORS);
                for (X509CertificateInformationAccessDescriptor informationAccessDescriptor : descriptors) {
                    serializeSia(doc, siaDescriptors, informationAccessDescriptor);
                }
            }
            return serialize(doc);

        } catch (ParserConfigurationException | TransformerException e) {
            throw new DomXmlSerializerException(e);
        }
    }
    private void serializeRevocationRequest(Document doc, Element revocationRequestElement, RevocationRequest revocationRequest) {
        addChild(doc, revocationRequestElement, REQUEST_ID)
            .setTextContent(revocationRequest.getRequestId().toString());

        addChild(doc, revocationRequestElement, RESOURCE_CLASS_NAME)
            .setTextContent(revocationRequest.getResourceClassName());

        addChild(doc, revocationRequestElement, ENCODED_REVOCATION_PUBLIC_KEY)
            .setTextContent(revocationRequest.getEncodedPublicKey());
    }

    private void serializeSigningRequest(Document doc, Element signingRequestElement, SigningRequest signingRequest) {
        addChild(doc, signingRequestElement, REQUEST_ID)
            .setTextContent(signingRequest.getRequestId().toString());

        final Element resourceCertificateRequestElement = addChild(doc, signingRequestElement, RESOURCE_CERTIFICATE_REQUEST);
        addChild(doc, resourceCertificateRequestElement, RESOURCE_CLASS_NAME)
            .setTextContent(signingRequest.getResourceCertificateRequest().getResourceClassName());

        addChild(doc, resourceCertificateRequestElement, SUBJECT_DN)
            .setTextContent(signingRequest.getResourceCertificateRequest().getSubjectDN().getName());

        addChild(doc, resourceCertificateRequestElement, ENCODED_SIGNING_SUBJECT_PUBLIC_KEY)
            .setTextContent(BASE64_ENCODER.encodeToString(signingRequest.getResourceCertificateRequest().getEncodedSubjectPublicKey()));

        final Element subjectInformationAccessElement = addChild(doc, resourceCertificateRequestElement, SUBJECT_INFORMATION_ACCESS);
        for (X509CertificateInformationAccessDescriptor informationAccessDescriptor: signingRequest.getResourceCertificateRequest().getSubjectInformationAccess()) {
            serializeSia(doc, subjectInformationAccessElement, informationAccessDescriptor);
        }
    }

    private void serializeSia(Document doc, Element subjectInformationAccessElement, X509CertificateInformationAccessDescriptor informationAccessDescriptor) {
        final Element x509CertificateInformationAccessDescriptorElement = addChild(doc, subjectInformationAccessElement, X_509_CERTIFICATE_INFORMATION_ACCESS_DESCRIPTOR);

        addChild(doc, x509CertificateInformationAccessDescriptorElement, METHOD)
            .setTextContent(informationAccessDescriptor.getMethod().toString());

        addChild(doc, x509CertificateInformationAccessDescriptorElement, LOCATION)
            .setTextContent(informationAccessDescriptor.getLocation().toString());
    }

    @Override
    public TrustAnchorRequest deserialize(final String xml) {
        try (final Reader characterStream = new StringReader(xml)) {
            final Document doc = getDocumentBuilder().parse(new InputSource(characterStream));

            final Element taRequestElement = getElementWithLegacyName(doc, REQUESTS_TRUST_ANCHOR_REQUEST)
                    .orElseThrow(() -> new DomXmlSerializerException("requests.TrustAnchorRequest element not found"));

            final Element creationTimestampElement = getSingleChildElement(taRequestElement, CREATION_TIMESTAMP);
            final String creationTimeStampText = getElementTextContent(creationTimestampElement);
            final Long creationTimeStamp;
            try {
                creationTimeStamp = Long.parseLong(creationTimeStampText);
            }catch (NumberFormatException e) {
                throw new DomXmlSerializerException("creationTimestamp content is not a number: " + creationTimeStampText, e);
            }

            final Element taCertificatePublicationUriElement = getSingleChildElement(taRequestElement, TA_CERTIFICATE_PUBLICATION_URI);
            final URI taCertificatePublicationUri = URI.create(getElementTextContent(taCertificatePublicationUriElement));

            final Element requestsListElement = getSingleChildElement(taRequestElement, TA_REQUESTS);
            final List<TaRequest> taRequests = getTaSigningRequests(requestsListElement);
            taRequests.addAll(getTaRevocationRequests(requestsListElement));

            final Element siaDescriptorsElement = getSingleChildElement(taRequestElement, SIA_DESCRIPTORS);
            final X509CertificateInformationAccessDescriptor[] x509CertificateInformationAccessDescriptors = getX509CertificateInformationAccessDescriptorArray(siaDescriptorsElement);

            final TrustAnchorRequest trustAnchorRequest = new TrustAnchorRequest(taCertificatePublicationUri, x509CertificateInformationAccessDescriptors, taRequests);

            setField(TrustAnchorRequest.class, trustAnchorRequest, "creationTimestamp", creationTimeStamp);

            return trustAnchorRequest;

        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    private X509CertificateInformationAccessDescriptor[] getX509CertificateInformationAccessDescriptorArray(Element parent) {
        final List<Element> x509CertificateInformationAccessDescriptorElements = getChildElements(parent, X_509_CERTIFICATE_INFORMATION_ACCESS_DESCRIPTOR);
        final X509CertificateInformationAccessDescriptor[] x509CertificateInformationAccessDescriptors =
            new X509CertificateInformationAccessDescriptor[x509CertificateInformationAccessDescriptorElements.size()];

        int i = 0;
        for (Element x509CertificateInformationAccessElement : x509CertificateInformationAccessDescriptorElements) {
            final Element methodElement = getSingleChildElement(x509CertificateInformationAccessElement, METHOD);
            final String method = getElementTextContent(methodElement);

            final Element locationElement = getSingleChildElement(x509CertificateInformationAccessElement, LOCATION);
            final String location = getElementTextContent(locationElement);

            x509CertificateInformationAccessDescriptors[i] = new X509CertificateInformationAccessDescriptor(new ASN1ObjectIdentifier(method), URI.create(location));
            i++;
        }

        return x509CertificateInformationAccessDescriptors;
    }

    private List<TaRequest> getTaRevocationRequests(Element taRequestElement) {
        List<TaRequest> taRequests = new ArrayList<>();
        final List<Element> revocationRequestElements = getChildElementsWithLegacyName(taRequestElement, REQUESTS_REVOCATION_REQUEST);
        for(Element revocationRequestElement: revocationRequestElements) {

            final Element resourceClassNameElement = getSingleChildElement(revocationRequestElement, RESOURCE_CLASS_NAME);
            final String resourceClassName = getElementTextContent(resourceClassNameElement);

            final Element encodedSubjectPublicKeyElement = getSingleChildElement(revocationRequestElement, ENCODED_REVOCATION_PUBLIC_KEY);
            final String encodedPublicKey = getElementTextContent(encodedSubjectPublicKeyElement);

            final TaRequest taRequest = new RevocationRequest(resourceClassName, encodedPublicKey);

            final Element requestIdElement = getSingleChildElement(revocationRequestElement, REQUEST_ID);
            final String requestId = getElementTextContent(requestIdElement);
            setField(TaRequest.class, taRequest, "requestId", UUID.fromString(requestId));
            taRequests.add(taRequest);
        }
        return taRequests;
    }

    private List<TaRequest> getTaSigningRequests(Element taRequestElement) {
        List<TaRequest> taRequests = new ArrayList<>();
        final List<Element> signingRequestElements = getChildElementsWithLegacyName(taRequestElement, REQUESTS_SIGNING_REQUEST);
        for(Element signingRequestElement: signingRequestElements) {
            final Element resourceCertificateRequestElement = getSingleChildElement(signingRequestElement, RESOURCE_CERTIFICATE_REQUEST);

            final Element resourceClassNameElement = getSingleChildElement(resourceCertificateRequestElement, RESOURCE_CLASS_NAME);
            final String resourceClassName = getElementTextContent(resourceClassNameElement);

            final Element subjectDNElement = getSingleChildElement(resourceCertificateRequestElement, SUBJECT_DN);
            final X500Principal subjectDN = new X500Principal(getElementTextContent(subjectDNElement));

            final Element encodedSubjectPublicKeyElement = getSingleChildElement(resourceCertificateRequestElement, ENCODED_SIGNING_SUBJECT_PUBLIC_KEY);
            final byte[] subjectPublicKey = BASE64_DECODER.decode(getElementTextContent(encodedSubjectPublicKeyElement));

            final Element subjectInformationAccessElement = getSingleChildElement(resourceCertificateRequestElement, SUBJECT_INFORMATION_ACCESS);

            final X509CertificateInformationAccessDescriptor[] x509CertificateInformationAccessDescriptors = getX509CertificateInformationAccessDescriptorArray(subjectInformationAccessElement);

            final TaRequest taRequest = new SigningRequest(new ResourceCertificateRequestData(resourceClassName, subjectDN, subjectPublicKey, x509CertificateInformationAccessDescriptors));

            final Element requestIdElement = getSingleChildElement(signingRequestElement, REQUEST_ID);
            final String requestId = getElementTextContent(requestIdElement);
            setField(TaRequest.class, taRequest, "requestId", UUID.fromString(requestId));
            taRequests.add(taRequest);
        }
        return taRequests;
    }

    private void setField(Class<?> clazz, Object obj, String fieldName, Object value) {
        try {
            Field privateField = clazz.getDeclaredField(fieldName);
            privateField.setAccessible(true);
            privateField.set(obj, value);
            privateField.setAccessible(false);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new DomXmlSerializerException("Unable to inject "+fieldName+": "+value + " into "+obj.getClass().getSimpleName(), e);
        }
    }

    protected List<Element> getChildElementsWithLegacyName(Element parent, String tagName) {
        final List<Element> childElements = getChildElements(parent, tagName);
        if(!childElements.isEmpty()) {
            return childElements;
        }

        return getChildElements(parent, "net.ripe.rpki.offline."+tagName);
    }


    private Optional<Element> getElementWithLegacyName(Document doc, String elementName) {
        final Optional<Element> element = getElement(doc, elementName);
        if(element.isPresent()) {
            return element;
        }

        return getElement(doc, "net.ripe.rpki.offline."+elementName);
    }
}
