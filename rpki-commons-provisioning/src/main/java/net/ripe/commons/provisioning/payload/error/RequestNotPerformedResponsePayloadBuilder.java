package net.ripe.commons.provisioning.payload.error;

import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

import org.apache.commons.lang.Validate;

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
    protected void onValidateFields() {
        Validate.notNull(error, "Error is required");
    }

    @Override
    public RequestNotPerformedResponsePayload build() {
        return new RequestNotPerformedResponsePayload(sender, recipient, error, description);
    }
}
