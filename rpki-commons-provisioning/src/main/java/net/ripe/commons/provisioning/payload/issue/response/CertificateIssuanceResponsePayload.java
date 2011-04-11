package net.ripe.commons.provisioning.payload.issue.response;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;
import net.ripe.commons.provisioning.payload.common.GenericClassElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateIssuanceResponsePayload extends AbstractProvisioningPayload {

    @XStreamAlias("class")
    private CertificateIssuanceResponseClassElement classElement;
    
    protected CertificateIssuanceResponsePayload(String sender, String recipient, CertificateIssuanceResponseClassElement classElement) {
        super(sender, recipient, PayloadMessageType.issue_response);
        this.classElement = classElement;
    }
    
    public GenericClassElement getClassElement() {
        return classElement;
    }

}
