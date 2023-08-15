package net.ripe.rpki.commons.provisioning.payload.list.response;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;

import java.util.Collections;
import java.util.List;

/**
 * See http://tools.ietf.org/html/rfc6492#section-3.3.2
 */
public class ResourceClassListResponsePayload extends AbstractProvisioningResponsePayload {

    private final List<ResourceClassListResponseClassElement> classElements;

    public ResourceClassListResponsePayload(List<ResourceClassListResponseClassElement> classElements) {
        super(PayloadMessageType.list_response);
        this.classElements = classElements;
    }

    public List<ResourceClassListResponseClassElement> getClassElements() {
        return classElements != null ? classElements : Collections.emptyList();
    }
}
