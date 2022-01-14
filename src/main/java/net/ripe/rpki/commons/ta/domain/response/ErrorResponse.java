package net.ripe.rpki.commons.ta.domain.response;


import java.util.UUID;

public class ErrorResponse extends TaResponse {

    private static final long serialVersionUID = 1L;

    private final String message;

    public ErrorResponse(UUID requestId, String message) {
        super(requestId);
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
