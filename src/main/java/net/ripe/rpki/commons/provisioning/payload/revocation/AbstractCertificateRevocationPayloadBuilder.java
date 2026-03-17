package net.ripe.rpki.commons.provisioning.payload.revocation;

import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.common.AbstractPayloadBuilder;

import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

public abstract class AbstractCertificateRevocationPayloadBuilder<T extends AbstractProvisioningPayload> extends AbstractPayloadBuilder<T> {

    private String className;
    private String publicKeyHash;

    public void withClassName(String className) {
        this.className = className;
    }


    public void withPublicKeyHash(String publicKeyHash) {
        this.publicKeyHash = publicKeyHash;
    }

    public void withPublicKey(PublicKey publicKey) {
        this.publicKeyHash = KeyPairUtil.getEncodedKeyIdentifier(publicKey);
    }

    protected void validateFields() {
        requireNonNull(className, "Classname is required");
        requireNonNull(publicKeyHash, "Public Key Hash is required");
    }

    protected String getClassName() {
        return className;
    }

    protected String getPublicKeyHash() {
        return publicKeyHash;
    }
}
