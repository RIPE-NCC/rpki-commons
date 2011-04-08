package net.ripe.commons.provisioning.message.list.response;

import java.util.ArrayList;
import java.util.List;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;

/**
 * Builder for 'Resource Class List Response'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2</a>
 */
public class ResourceClassListResponseCmsBuilder extends ProvisioningCmsObjectBuilder {

    private static final XStreamXmlSerializer<ResourceClassListResponsePayloadWrapper> SERIALIZER = new ResourceClassListResponsePayloadWrapperSerializerBuilder().build();
    
    private List<ResourceClassListResponseClassElement> classElements = new ArrayList<ResourceClassListResponseClassElement>();

    public void addClassElement(ResourceClassListResponseClassElement classElement) {
        classElements.add(classElement);
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        ResourceClassListResponsePayloadWrapper wrapper = new ResourceClassListResponsePayloadWrapper(sender, recipient, classElements);
        return SERIALIZER.serialize(wrapper);
    }
}
