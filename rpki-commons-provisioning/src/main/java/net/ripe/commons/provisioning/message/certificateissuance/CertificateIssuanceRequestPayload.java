package net.ripe.commons.provisioning.message.certificateissuance;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayload;

@XStreamAlias("message")
public class CertificateIssuanceRequestPayload extends ProvisioningPayload {

    @XStreamAlias("request")
    @XStreamConverter(CertificateIssuanceRequestContentConverter.class)
    private CertificateIssuanceRequestContent content;

    public CertificateIssuanceRequestPayload(String sender, String recipient, CertificateIssuanceRequestContent content) {
        super(sender, recipient, PayloadMessageType.issue);

        this.content = content;
    }

    public CertificateIssuanceRequestContent getPayloadContent() {
        return content;
    }


}
