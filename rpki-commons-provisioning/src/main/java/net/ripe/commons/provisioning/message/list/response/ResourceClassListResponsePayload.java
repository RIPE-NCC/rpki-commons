package net.ripe.commons.provisioning.message.list.response;

import java.util.List;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamImplicit;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.AbstractProvisioningPayload;
import org.apache.commons.lang.builder.ToStringBuilder;

@XStreamAlias("message")
public class ResourceClassListResponsePayload extends AbstractProvisioningPayload {

    @XStreamImplicit(itemFieldName = "class")
    private List<ResourceClassListResponseClassElement> classElements;

    public ResourceClassListResponsePayload(String sender, String recipient, List<ResourceClassListResponseClassElement> classElements) {
        super(sender, recipient, PayloadMessageType.list_response);
        this.classElements = classElements;
    }

    public List<ResourceClassListResponseClassElement> getClassElements() {
        return classElements;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
