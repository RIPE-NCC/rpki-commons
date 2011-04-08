package net.ripe.commons.provisioning.message.issue.request;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.AbstractProvisioningPayload;

@XStreamAlias("message")
public class CertificateIssuanceRequestPayload extends AbstractProvisioningPayload {

    @XStreamAlias("request")
    @XStreamConverter(CertificateIssuanceRequestElementConverter.class)
    private CertificateIssuanceRequestElement requestElement;

    public CertificateIssuanceRequestPayload(String sender, String recipient, CertificateIssuanceRequestElement requestElement) {
        super(sender, recipient, PayloadMessageType.issue);

        this.requestElement = requestElement;
    }

    public CertificateIssuanceRequestElement getRequestElement() {
        return requestElement;
    }
}
