package net.ripe.rpki.commons.provisioning.identity;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.util.EqualsSupport;

import java.util.UUID;

public class ChildIdentity extends EqualsSupport {

    public static final int VERSION = 1;
    private String handle;
    private ProvisioningIdentityCertificate identityCertificate;


    /**
     * Create a child identity to offer to your parent with a random UUID based handle.
     */
    public ChildIdentity(ProvisioningIdentityCertificate identityCertificate) {
        this(UUID.randomUUID().toString(), identityCertificate);
    }

    /**
     * Create a child identity to offer to your parent, including a suggested handle. Note that
     * your parent may ignore this handle!
     */
    public ChildIdentity(String handle, ProvisioningIdentityCertificate identityCertificate) {
        this.handle = handle;
        this.identityCertificate = identityCertificate;
    }

    public String getHandle() {
        return handle;
    }

    public int getVersion() {
        return VERSION;
    }

    public ProvisioningIdentityCertificate getIdentityCertificate() {
        return identityCertificate;
    }

}
