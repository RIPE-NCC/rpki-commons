package net.ripe.commons.provisioning.message.issue.response;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;
import net.ripe.commons.provisioning.message.common.GenericClassElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateIssuanceResponsePayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("class")
    private CertificateIssuanceResponseClassElement classElement;
    
    protected CertificateIssuanceResponsePayloadWrapper(String sender, String recipient, CertificateIssuanceResponseClassElement classElement) {
        super(sender, recipient, PayloadMessageType.issue_response);
        this.classElement = classElement;
    }
    
    public GenericClassElement getClassElement() {
        return classElement;
    }

}
