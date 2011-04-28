package net.ripe.commons.provisioning.identity;

import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

/**
 * Wrapper class for the identity information relevant to <b>MY CHILD</b> in the provisioning protocol
 */
public class ChildIdentityMaterial {
    
    private ProvisioningIdentityCertificate childCertificate;

    public ChildIdentityMaterial(ProvisioningIdentityCertificate childCertificate) {
        this.childCertificate = childCertificate;
    }
    
    public ProvisioningIdentityCertificate getChildCertificate() {
        return childCertificate;
    }

}
