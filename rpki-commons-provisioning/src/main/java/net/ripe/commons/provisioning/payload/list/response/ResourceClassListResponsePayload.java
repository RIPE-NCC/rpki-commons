package net.ripe.commons.provisioning.payload.list.response;

import java.util.List;

import net.ripe.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

import org.apache.commons.lang.builder.ToStringBuilder;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamImplicit;

@XStreamAlias("message")
public class ResourceClassListResponsePayload extends AbstractProvisioningResponsePayload {

    @XStreamImplicit(itemFieldName = "class")
    private List<ResourceClassListResponseClassElement> classElements;

    public ResourceClassListResponsePayload(List<ResourceClassListResponseClassElement> classElements) {
        super(PayloadMessageType.list_response);
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
