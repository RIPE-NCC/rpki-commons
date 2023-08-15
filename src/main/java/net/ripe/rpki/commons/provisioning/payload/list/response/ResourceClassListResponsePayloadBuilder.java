package net.ripe.rpki.commons.provisioning.payload.list.response;

import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * Builder for 'Resource Class List Response'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2</a>
 */
public class ResourceClassListResponsePayloadBuilder extends AbstractPayloadBuilder<ResourceClassListResponsePayload> {

    private final List<ResourceClassListResponseClassElement> classElements = new ArrayList<>();

    public void addClassElement(ResourceClassListResponseClassElement classElement) {
        classElements.add(classElement);
    }

    @Override
    public ResourceClassListResponsePayload build() {
        return new ResourceClassListResponsePayload(classElements);
    }
}
