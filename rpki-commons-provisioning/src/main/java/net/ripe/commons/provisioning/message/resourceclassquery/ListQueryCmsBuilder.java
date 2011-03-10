package net.ripe.commons.provisioning.message.resourceclassquery;


import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilderException;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadBuilder;

import java.io.IOException;
import java.security.PrivateKey;

public class ListQueryCmsBuilder extends ProvisioningPayloadBuilder {

    public ListQueryCmsBuilder() {
        super(PayloadMessageType.list);
    }

    public ProvisioningCmsObject build(PrivateKey privateKey)  {
        try {
            String xml = serializePayload();
            withPayloadContent(xml);
            return super.build(privateKey);
        } catch (IOException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        }
    }

}
