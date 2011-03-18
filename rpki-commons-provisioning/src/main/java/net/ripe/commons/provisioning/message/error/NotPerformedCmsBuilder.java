package net.ripe.commons.provisioning.message.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.CommonCmsBuilder;
import org.apache.commons.lang.Validate;

public class NotPerformedCmsBuilder extends CommonCmsBuilder {
    private static final XStreamXmlSerializer<NotPerformedPayloadWrapper> SERIALIZER = new NotPerformedPayloadSerializerBuilder().build();

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
        NotPerformedPayloadWrapper payload = new NotPerformedPayloadWrapper(sender, recipient, error, description);

        String xml = SERIALIZER.serialize(payload);

        return xml.replace("<description>", "<description xml:lang=\"en-US\">");
    }
}
