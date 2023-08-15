package net.ripe.rpki.commons.provisioning.payload;

import net.ripe.rpki.commons.util.EqualsSupport;

public abstract class AbstractProvisioningPayload extends EqualsSupport {

    public static final String DEFAULT_SENDER = "sender";
    public static final String DEFAULT_RECIPIENT = "recipient";

    public static final Integer SUPPORTED_VERSION = 1;

    private final Integer version;

    private String sender = DEFAULT_SENDER;

    private String recipient = DEFAULT_RECIPIENT;

    private final PayloadMessageType type;

    protected AbstractProvisioningPayload(PayloadMessageType type) {
        this(SUPPORTED_VERSION, type);
    }

    protected AbstractProvisioningPayload(Integer version, PayloadMessageType type) {
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
