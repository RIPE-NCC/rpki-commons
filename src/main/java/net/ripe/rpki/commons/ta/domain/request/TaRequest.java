package net.ripe.rpki.commons.ta.domain.request;


import lombok.EqualsAndHashCode;

import java.io.Serializable;
import java.util.UUID;

@EqualsAndHashCode
public abstract class TaRequest implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final UUID requestId;

    public TaRequest() {
        this.requestId = UUID.randomUUID();
    }

    public UUID getRequestId() {
        return requestId;
    }
}
