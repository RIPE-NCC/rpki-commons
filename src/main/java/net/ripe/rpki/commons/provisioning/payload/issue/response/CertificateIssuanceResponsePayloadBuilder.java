package net.ripe.rpki.commons.provisioning.payload.issue.response;

import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;
import org.apache.commons.lang3.Validate;


/**
 * Builder for 'Certificate Issuance Response'<br >
 * See: <a href="http://tools.ietf.org/html/rfc6492#section-3.4.2">http://tools.ietf.org/html/rfc6492#section-3.4.2</a>
 */
public class CertificateIssuanceResponsePayloadBuilder extends AbstractPayloadBuilder<CertificateIssuanceResponsePayload> {

    private CertificateIssuanceResponseClassElement classElement;

    public CertificateIssuanceResponsePayloadBuilder withClassElement(CertificateIssuanceResponseClassElement classElement) {
        this.classElement = classElement;
        return this;
    }

    @Override
    public CertificateIssuanceResponsePayload build() {
        Validate.notNull(classElement, "Need one ClassElement");
        return new CertificateIssuanceResponsePayload(classElement);
    }

}
