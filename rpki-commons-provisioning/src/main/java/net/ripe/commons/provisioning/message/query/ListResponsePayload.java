package net.ripe.commons.provisioning.message.query;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import net.ripe.commons.provisioning.message.common.ResourceClassPayload;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.joda.time.DateTime;

@XStreamAlias("class")
public class ListResponsePayload extends ResourceClassPayload {
    @XStreamAlias("resource_set_notafter")
    @XStreamAsAttribute
    private DateTime validityNotAfter;

    @XStreamAlias("suggested_sia_head")
    @XStreamAsAttribute
    private String siaHeadUri;

    public DateTime getValidityNotAfter() {
        return validityNotAfter;
    }

    ListResponsePayload setValidityNotAfter(DateTime validityNotAfter) {
        this.validityNotAfter = validityNotAfter;
        return this;
    }

    public String getSiaHeadUri() {
        return siaHeadUri;
    }

    ListResponsePayload setSiaHeadUri(String siaHeadUri) {
        this.siaHeadUri = siaHeadUri;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
