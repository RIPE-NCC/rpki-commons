package net.ripe.rpki.commons.provisioning.payload.list.request;


import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;

/**
 * Builder for 'Resource Class List Query'<br >
 * See: <a href="https://datatracker.ietf.org/doc/html/rfc6492#section-3.3.1">https://datatracker.ietf.org/doc/html/rfc6492#section-3.3.1</a>
 */
public class ResourceClassListQueryPayloadBuilder extends AbstractPayloadBuilder<ResourceClassListQueryPayload> {

    @Override
    public ResourceClassListQueryPayload build() {
        return new ResourceClassListQueryPayload();
    }
}
