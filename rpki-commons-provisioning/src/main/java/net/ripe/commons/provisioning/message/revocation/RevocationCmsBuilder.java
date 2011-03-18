package net.ripe.commons.provisioning.message.revocation;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.CommonCmsBuilder;
import org.apache.commons.lang.Validate;

public class RevocationCmsBuilder extends CommonCmsBuilder {
    private static final XStreamXmlSerializer<RevocationPayloadWrapper> SERIALIZER = new RevocationPayloadWrapperSerializerBuilder().build();

    private String className;
    private String ski;

    public void withClassName(String className) {
        this.className = className;
    }

    public void withSki(String ski) {
        this.ski = ski;
    }

    @Override
    protected void onValidateFields() {
        Validate.notNull(className, "Classname is required");
        Validate.notNull(ski, "SKI is required");
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        RevocationPayload payload = new RevocationPayload(className, ski);

        RevocationPayloadWrapper wrapper = new RevocationPayloadWrapper(sender, recipient, payload);

        return SERIALIZER.serialize(wrapper);
    }
}
