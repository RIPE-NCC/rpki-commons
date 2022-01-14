package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningQueryPayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;

/**
 * See: http://tools.ietf.org/html/rfc6492#section-3.4.1
 */
public class CertificateIssuanceRequestPayload extends AbstractProvisioningQueryPayload {

    private CertificateIssuanceRequestElement requestElement;

    public CertificateIssuanceRequestPayload(CertificateIssuanceRequestElement requestElement) {
        super(PayloadMessageType.issue);

        this.requestElement = requestElement;
    }

    public CertificateIssuanceRequestElement getRequestElement() {
        return requestElement;
    }
}
