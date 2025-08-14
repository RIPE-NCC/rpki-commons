package net.ripe.rpki.commons.ta.domain.request;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.commons.lang3.Validate;

@Getter
@EqualsAndHashCode(callSuper = true)
public class SigningRequest extends TaRequest {

    private static final long serialVersionUID = 1L;

    private final ResourceCertificateRequestData resourceCertificateRequest;

    public SigningRequest(ResourceCertificateRequestData resourceCertificateRequest) {
        Validate.notNull(resourceCertificateRequest, "resourceCertificateRequest is required");
        this.resourceCertificateRequest = resourceCertificateRequest;
    }
}
