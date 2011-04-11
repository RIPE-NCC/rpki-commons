package net.ripe.commons.provisioning.payload.revocation;

import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

import org.apache.commons.lang.Validate;

import java.security.PublicKey;


public abstract class AbstractCertificateRevocationPayloadBuilder extends AbstractPayloadBuilder {

    protected String className;
    protected PublicKey publicKey;

    public AbstractCertificateRevocationPayloadBuilder() {
        super();
    }

    public void withClassName(String className) {
        this.className = className;
    }

    public void withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    protected void onValidateFields() {
        Validate.notNull(className, "Classname is required");
        Validate.notNull(publicKey, "Public Key is required");
    }

}
