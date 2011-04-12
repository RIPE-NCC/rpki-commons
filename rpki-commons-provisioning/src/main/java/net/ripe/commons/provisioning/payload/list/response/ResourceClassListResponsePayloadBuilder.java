package net.ripe.commons.provisioning.payload.list.response;

import java.util.ArrayList;
import java.util.List;

import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

/**
 * Builder for 'Resource Class List Response'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2</a>
 */
public class ResourceClassListResponsePayloadBuilder extends AbstractPayloadBuilder<ResourceClassListResponsePayload> {

    private List<ResourceClassListResponseClassElement> classElements = new ArrayList<ResourceClassListResponseClassElement>();

    public void addClassElement(ResourceClassListResponseClassElement classElement) {
        classElements.add(classElement);
    }

    @Override
    public ResourceClassListResponsePayload build() {
        onValidateFields();
        return new ResourceClassListResponsePayload(sender, recipient, classElements);
    }
}
