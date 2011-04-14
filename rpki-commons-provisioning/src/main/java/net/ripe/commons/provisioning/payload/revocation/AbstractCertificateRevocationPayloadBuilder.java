package net.ripe.commons.provisioning.payload.revocation;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

import org.apache.commons.lang.Validate;

import java.security.PublicKey;

public abstract class AbstractCertificateRevocationPayloadBuilder<T extends AbstractProvisioningPayload> extends AbstractPayloadBuilder<T> {

    private String className;
    private PublicKey publicKey;

    public void withClassName(String className) {
        this.className = className;
    }

    public void withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    protected void validateFields() {
        Validate.notNull(className, "Classname is required");
        Validate.notNull(publicKey, "Public Key is required");
    }

    protected String getClassName() {
        return className;
    }

    protected PublicKey getPublicKey() {
        return publicKey;
    }
}
