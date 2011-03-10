package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadBuilder;

public class ListResponseCmsBuilder extends ProvisioningPayloadBuilder {

    protected ListResponseCmsBuilder() {
        super(PayloadMessageType.list_response);
    }
}
