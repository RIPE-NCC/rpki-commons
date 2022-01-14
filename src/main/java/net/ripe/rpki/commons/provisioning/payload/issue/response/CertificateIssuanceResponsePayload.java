package net.ripe.rpki.commons.provisioning.payload.issue.response;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;

/**
 * See: http://tools.ietf.org/html/rfc6492#section-3.4.2
 */
public class CertificateIssuanceResponsePayload extends AbstractProvisioningResponsePayload {

    private CertificateIssuanceResponseClassElement classElement;

    protected CertificateIssuanceResponsePayload(CertificateIssuanceResponseClassElement classElement) {
        super(PayloadMessageType.issue_response);
        this.classElement = classElement;
    }

    public CertificateIssuanceResponseClassElement getClassElement() {
        return classElement;
    }

}
