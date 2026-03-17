package net.ripe.rpki.commons.ta.domain.response;


import net.ripe.rpki.commons.util.EqualsSupport;

import java.io.Serializable;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public abstract class TaResponse extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private UUID requestId;

    protected TaResponse(UUID requestId) {
        requireNonNull(requestId, "requestId is required");
        this.requestId = requestId;
    }

    public UUID getRequestId() {
        return requestId;
    }
}
