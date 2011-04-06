package net.ripe.commons.provisioning.message.query;


import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.CommonCmsBuilder;

public class ListQueryCmsBuilder extends CommonCmsBuilder {

    private static final XStreamXmlSerializer<ListQueryPayloadWrapper> SERIALIZER = new ListQueryPayloadSerializerBuilder().build();


    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        ListQueryPayloadWrapper payload = new ListQueryPayloadWrapper(sender, recipient);
        return SERIALIZER.serialize(payload);
    }
}
