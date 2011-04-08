package net.ripe.commons.provisioning.message.list.response;

import java.util.List;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamImplicit;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;
import org.apache.commons.lang.builder.ToStringBuilder;

@XStreamAlias("message")
public class ResourceClassListResponsePayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamImplicit(itemFieldName = "class")
    private List<ResourceClassListResponseClassElement> resourceClassList;

    public ResourceClassListResponsePayloadWrapper(String sender, String recipient, List<ResourceClassListResponseClassElement> classElements) {
        super(sender, recipient, PayloadMessageType.list_response);
        this.resourceClassList = classElements;
    }

    public List<ResourceClassListResponseClassElement> getClassElements() {
        return resourceClassList;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
