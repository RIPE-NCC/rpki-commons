package net.ripe.commons.provisioning.identity;

import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

import java.io.Serializable;

/**
 * Wrapper class for the identity information relevant to <b>MY CHILD</b> in the provisioning protocol
 */
public class ChildIdentityMaterial implements Serializable {

    private static final long serialVersionUID = 1L;

    private ProvisioningIdentityCertificate childCertificate;

    public ChildIdentityMaterial(ProvisioningIdentityCertificate childCertificate) {
        this.childCertificate = childCertificate;
    }

    public ProvisioningIdentityCertificate getChildCertificate() {
        return childCertificate;
    }

}
