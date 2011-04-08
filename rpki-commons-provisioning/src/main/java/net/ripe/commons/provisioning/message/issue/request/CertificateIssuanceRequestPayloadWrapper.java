package net.ripe.commons.provisioning.message.issue.request;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

@XStreamAlias("message")
public class CertificateIssuanceRequestPayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("request")
    @XStreamConverter(CertificateIssuanceRequestPayloadConverter.class)
    private CertificateIssuanceRequestPayload content;

    public CertificateIssuanceRequestPayloadWrapper(String sender, String recipient, CertificateIssuanceRequestPayload content) {
        super(sender, recipient, PayloadMessageType.issue);

        this.content = content;
    }

    public CertificateIssuanceRequestPayload getPayloadContent() {
        return content;
    }
}
