package net.ripe.rpki.commons.ta.domain.response;


import org.apache.commons.lang3.Validate;

import java.util.UUID;

public class RevocationResponse extends TaResponse {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final String encodedPublicKey;

    public RevocationResponse(UUID requestId, String resourceClassName, String encodedPublicKey) {
        super(requestId);
        Validate.notNull(resourceClassName, "resourceClassName is required");
        Validate.notNull(encodedPublicKey, "encodedPublicKey is required");
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
