package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.ResourceClassCmsBuilder;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class ListResponseCmsBuilder extends ResourceClassCmsBuilder {

    private static final XStreamXmlSerializer<ListResponsePayloadWrapper> SERIALIZER = new ListResponsePayloadWrapperSerializerBuilder().build();
    private DateTime validityNotAfter;
    private String siaHeadUri;

    public void withValidityNotAfter(DateTime notAfter) {
        this.validityNotAfter = notAfter;
    }

    public void withSiaHeadUri(String siaHead) {
        this.siaHeadUri = siaHead;
    }

    @Override
    protected void onValidateAdditionalFields() {
        Validate.notNull(validityNotAfter, "Validity not after is required");
        Validate.isTrue(validityNotAfter.getZone().equals(DateTimeZone.UTC), "Validity time must be in UTC timezone");
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        ListResponsePayload payload = new ListResponsePayload();
        payload.setValidityNotAfter(validityNotAfter);
        payload.setSiaHeadUri(siaHeadUri);

        super.setValuesInPayload(payload);

        ListResponsePayloadWrapper wrapper = new ListResponsePayloadWrapper(sender, recipient, payload);

        return SERIALIZER.serialize(wrapper);
    }
}
