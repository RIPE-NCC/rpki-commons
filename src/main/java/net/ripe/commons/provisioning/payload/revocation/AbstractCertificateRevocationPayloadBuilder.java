package net.ripe.commons.provisioning.payload.revocation;

import java.security.PublicKey;

import net.ripe.commons.certification.util.KeyPairUtil;
import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

import org.apache.commons.lang.Validate;

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
        Validate.notNull(className, "Classname is required");
        Validate.notNull(publicKeyHash, "Public Key Hash is required");
    }

    protected String getClassName() {
        return className;
    }

    protected String getPublicKeyHash() {
        return publicKeyHash;
    }
}
