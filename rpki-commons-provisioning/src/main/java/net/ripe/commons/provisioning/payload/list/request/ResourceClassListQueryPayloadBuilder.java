package net.ripe.commons.provisioning.payload.list.request;


import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

/**
 * Builder for 'Resource Class List Query'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1</a>
 */
public class ResourceClassListQueryPayloadBuilder extends AbstractPayloadBuilder {

    private static final XStreamXmlSerializer<ResourceClassListQueryPayload> SERIALIZER = new ResourceClassListQueryPayloadSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        ResourceClassListQueryPayload payload = new ResourceClassListQueryPayload(sender, recipient);
        return SERIALIZER.serialize(payload);
    }
}
