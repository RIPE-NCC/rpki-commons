package net.ripe.rpki.commons.provisioning.payload.error;

import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;
import org.apache.commons.lang3.Validate;

/**
 * Build a NotPerformed message, see <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.6">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.6</a>
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
        Validate.notNull(error, "Error is required");
        return new RequestNotPerformedResponsePayload(error, description);
    }
}
