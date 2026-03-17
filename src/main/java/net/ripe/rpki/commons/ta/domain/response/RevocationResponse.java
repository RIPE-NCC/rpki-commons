package net.ripe.rpki.commons.ta.domain.response;

import java.util.UUID;

import static java.util.Objects.requireNonNull;

public class RevocationResponse extends TaResponse {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final String encodedPublicKey;

    public RevocationResponse(UUID requestId, String resourceClassName, String encodedPublicKey) {
        super(requestId);
        requireNonNull(resourceClassName, "resourceClassName is required");
        requireNonNull(encodedPublicKey, "encodedPublicKey is required");
        this.resourceClassName = resourceClassName;
        this.encodedPublicKey = encodedPublicKey;
    }

    public String getResourceClassName() {
        return resourceClassName;
    }

    public String getEncodedPublicKey() {
        return encodedPublicKey;
    }
}
