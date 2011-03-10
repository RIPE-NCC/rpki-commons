package net.ripe.commons.provisioning.message;

class ProvisioningPayload {
    private Integer version;
    private String sender;
    private String recipient;
    private PayloadMessageType type;

    ProvisioningPayload(Integer version, String sender, String recipient, PayloadMessageType type) {
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
}
