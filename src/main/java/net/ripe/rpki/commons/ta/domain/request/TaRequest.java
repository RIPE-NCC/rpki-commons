package net.ripe.rpki.commons.ta.domain.request;


import net.ripe.rpki.commons.util.EqualsSupport;

import java.io.Serializable;
import java.util.UUID;

public abstract class TaRequest extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final UUID requestId;

    public TaRequest() {
        this.requestId = UUID.randomUUID();
    }

    public UUID getRequestId() {
        return requestId;
    }
}
