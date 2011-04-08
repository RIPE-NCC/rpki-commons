package net.ripe.commons.provisioning.message.issue.response;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.message.common.GenericClassElement;

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
