package net.ripe.rpki.commons.provisioning.payload.error;

import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;

import static java.util.Objects.requireNonNull;

/**
 * Build a NotPerformed message, see <a href="https://datatracker.ietf.org/doc/html/rfc6492#section-3.6">https://datatracker.ietf.org/doc/html/rfc6492#section-3.6</a>
 */
public class RequestNotPerformedResponsePayloadBuilder extends AbstractPayloadBuilder<RequestNotPerformedResponsePayload> {

    private NotPerformedError error;
    private String description;

    public void withError(NotPerformedError error) {
        this.error = error;
    }

    public void withDescription(String description) {
        this.description = description;
    }

    @Override
    public RequestNotPerformedResponsePayload build() {
        requireNonNull(error, "Error is required");
        return new RequestNotPerformedResponsePayload(error, description);
    }
}
