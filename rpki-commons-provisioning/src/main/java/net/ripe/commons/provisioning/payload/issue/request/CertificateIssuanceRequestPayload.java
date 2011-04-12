package net.ripe.commons.provisioning.payload.issue.request;

import net.ripe.commons.provisioning.payload.AbstractProvisioningQueryPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;

@XStreamAlias("message")
public class CertificateIssuanceRequestPayload extends AbstractProvisioningQueryPayload {

    @XStreamAlias("request")
    @XStreamConverter(CertificateIssuanceRequestElementConverter.class)
    private CertificateIssuanceRequestElement requestElement;

    public CertificateIssuanceRequestPayload(CertificateIssuanceRequestElement requestElement) {
        super(PayloadMessageType.issue);

        this.requestElement = requestElement;
    }

    public CertificateIssuanceRequestElement getRequestElement() {
        return requestElement;
    }
}
