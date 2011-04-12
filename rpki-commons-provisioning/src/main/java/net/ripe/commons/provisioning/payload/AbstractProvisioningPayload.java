package net.ripe.commons.provisioning.payload;

import com.thoughtworks.xstream.annotations.XStreamAsAttribute;

public abstract class AbstractProvisioningPayload {
    
    public static final String DEFAULT_SENDER = "sender";
    public static final String DEFAULT_RECIPIENT = "recipient";

    private static final Integer SUPPORTED_VERSION = 1;

    @XStreamAsAttribute
    private Integer version;

    @XStreamAsAttribute
    private String sender = DEFAULT_SENDER;

    @XStreamAsAttribute
    private String recipient = DEFAULT_RECIPIENT;

    @XStreamAsAttribute
    private PayloadMessageType type;

    protected AbstractProvisioningPayload(PayloadMessageType type) {
        this(SUPPORTED_VERSION, type);
    }

    private AbstractProvisioningPayload(Integer version, PayloadMessageType type) {
        this.version = version;
        this.type = type;
    }
    
    /**
     * Note: This field is used by some implementations to work out who the players
     * are in an exchange of ProvisioningCmsObjects. (eg APNIC). This setter is
     * provided to make it easier to set this value 'close' to your code that deals
     * with this actual exchange, as opposed to the code that deals with the other
     * 'content' of the payload.
     */
    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }
    
    /**
     * Note: This field is used by some implementations to work out who the players
     * are in an exchange of ProvisioningCmsObjects. (eg APNIC). This setter is
     * provided to make it easier to set this value 'close' to your code that deals
     * with this actual exchange, as opposed to the code that deals with the other
     * 'content' of the payload.
     */
    public void setSender(String sender) {
        this.sender = sender;
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
    
}
