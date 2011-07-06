package net.ripe.commons.provisioning.payload.list.request;


import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

/**
 * Builder for 'Resource Class List Query'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1</a>
 */
public class ResourceClassListQueryPayloadBuilder extends AbstractPayloadBuilder<ResourceClassListQueryPayload> {

    @Override
    public ResourceClassListQueryPayload build() {
        return new ResourceClassListQueryPayload();
    }
}
