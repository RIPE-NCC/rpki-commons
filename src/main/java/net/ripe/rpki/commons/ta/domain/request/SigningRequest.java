package net.ripe.rpki.commons.ta.domain.request;

import static java.util.Objects.requireNonNull;

public class SigningRequest extends TaRequest {

    private static final long serialVersionUID = 1L;

    private final ResourceCertificateRequestData resourceCertificateRequest;

    public SigningRequest(ResourceCertificateRequestData resourceCertificateRequest) {
        requireNonNull(resourceCertificateRequest, "resourceCertificateRequest is required");
        this.resourceCertificateRequest = resourceCertificateRequest;
    }

    public ResourceCertificateRequestData getResourceCertificateRequest() {
        return resourceCertificateRequest;
    }
}
