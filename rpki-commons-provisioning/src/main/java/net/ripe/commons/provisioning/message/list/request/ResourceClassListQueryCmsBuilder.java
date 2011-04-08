package net.ripe.commons.provisioning.message.list.request;


import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;

/**
 * Builder for 'Resource Class List Query'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1</a>
 */
public class ResourceClassListQueryCmsBuilder extends ProvisioningCmsObjectBuilder {

    private static final XStreamXmlSerializer<ResourceClassListQueryPayloadWrapper> SERIALIZER = new ResourceClassListQueryPayloadSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        ResourceClassListQueryPayloadWrapper payload = new ResourceClassListQueryPayloadWrapper(sender, recipient);
        return SERIALIZER.serialize(payload);
    }
}
