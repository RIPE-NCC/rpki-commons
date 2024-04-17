package net.ripe.rpki.commons.ta.domain.request;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

/**
 * Ask Trust Anchor to revoke all certificates that use the provided public key.
 */
@Getter
@EqualsAndHashCode(callSuper = true)
public class RevocationRequest extends TaRequest {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final String encodedPublicKey;

    public RevocationRequest(String resourceClassName, String encodedPublicKey) {
        this.resourceClassName = resourceClassName;
        this.encodedPublicKey = encodedPublicKey;
    }
}
