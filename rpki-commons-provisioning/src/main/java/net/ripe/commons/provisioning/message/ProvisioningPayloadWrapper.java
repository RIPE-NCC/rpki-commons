package net.ripe.commons.provisioning.message;

import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import org.apache.commons.lang.builder.ToStringBuilder;

public abstract class ProvisioningPayloadWrapper {
    private static final Integer SUPPORTED_VERSION = 1;

    @XStreamAsAttribute
    private Integer version;

    @XStreamAsAttribute
    private String sender;

    @XStreamAsAttribute
    private String recipient;

    @XStreamAsAttribute
    private PayloadMessageType type;

    public ProvisioningPayloadWrapper(String sender, String recipient, PayloadMessageType type) {
        this(SUPPORTED_VERSION, sender, recipient, type);
    }

    public ProvisioningPayloadWrapper(Integer version, String sender, String recipient, PayloadMessageType type) {
        this.version = version;
        this.sender = sender;
        this.recipient = recipient;
        this.type = type;
    }

    public Integer getVersion() {
        return version;
    }

    public String getSender() {
        return sender;
    }

    public String getRecipient() {
        return recipient;
    }

    public PayloadMessageType getType() {
        return type;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public void setType(PayloadMessageType type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
