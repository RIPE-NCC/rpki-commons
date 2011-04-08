package net.ripe.commons.provisioning.message.revocation;

import java.security.PublicKey;

import org.apache.commons.lang.Validate;

import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;


public abstract class AbstractCertificateRevocationCmsBuilder extends ProvisioningCmsObjectBuilder {

    protected String className;
    protected PublicKey publicKey;

    public AbstractCertificateRevocationCmsBuilder() {
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
