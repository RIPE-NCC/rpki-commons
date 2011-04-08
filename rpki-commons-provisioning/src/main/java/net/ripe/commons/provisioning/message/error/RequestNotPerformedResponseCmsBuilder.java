package net.ripe.commons.provisioning.message.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;

import org.apache.commons.lang.Validate;

/**
 * Build a NotPerformed message, see <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.6">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.6</a> 
 *
 */
public class RequestNotPerformedResponseCmsBuilder extends ProvisioningCmsObjectBuilder {
    
    private static final XStreamXmlSerializer<RequestNotPerformedResponsePayloadWrapper> SERIALIZER = new RequestNotPerformedResponsePayloadSerializerBuilder().build();

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
    protected String serializePayloadWrapper(String sender, String recipient) {
        RequestNotPerformedResponsePayloadWrapper payload = new RequestNotPerformedResponsePayloadWrapper(sender, recipient, error, description);

        String xml = SERIALIZER.serialize(payload);

        return xml.replace("<description>", "<description xml:lang=\"en-US\">");
    }
}
