package net.ripe.commons.provisioning.payload.issue.response;

import net.ripe.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;
import net.ripe.commons.provisioning.payload.common.GenericClassElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateIssuanceResponsePayload extends AbstractProvisioningResponsePayload {

    @XStreamAlias("class")
    private CertificateIssuanceResponseClassElement classElement;
    
    protected CertificateIssuanceResponsePayload(CertificateIssuanceResponseClassElement classElement) {
        super(PayloadMessageType.issue_response);
        this.classElement = classElement;
    }
    
    public GenericClassElement getClassElement() {
        return classElement;
    }

}
