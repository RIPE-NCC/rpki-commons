package net.ripe.rpki.commons.ta.domain.response;


import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import org.apache.commons.lang3.Validate;

import java.net.URI;
import java.util.UUID;

public class SigningResponse extends TaResponse {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final URI publicationUri;
    private final X509ResourceCertificate certificate;

    public SigningResponse(UUID requestId, String resourceClassName, URI publicationUri, X509ResourceCertificate certificate) {
        super(requestId);
        Validate.notNull(resourceClassName, "resourceClassName is required");
        Validate.notNull(publicationUri, "publicationUri is required");
        Validate.notNull(certificate, "certificate is required");
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
