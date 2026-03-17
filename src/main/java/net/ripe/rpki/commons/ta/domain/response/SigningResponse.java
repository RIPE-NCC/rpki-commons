package net.ripe.rpki.commons.ta.domain.response;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;

import java.net.URI;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public class SigningResponse extends TaResponse {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final URI publicationUri;
    private final X509ResourceCertificate certificate;

    public SigningResponse(UUID requestId, String resourceClassName, URI publicationUri, X509ResourceCertificate certificate) {
        super(requestId);
        requireNonNull(resourceClassName, "resourceClassName is required");
        requireNonNull(publicationUri, "publicationUri is required");
        requireNonNull(certificate, "certificate is required");
        this.resourceClassName = resourceClassName;
        this.publicationUri = publicationUri;
        this.certificate = certificate;
    }

    public String getResourceClassName() {
        return resourceClassName;
    }

    public URI getPublicationUri() {
        return publicationUri;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }
}
