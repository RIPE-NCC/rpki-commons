package net.ripe.commons.provisioning.identity;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

import java.io.Serializable;
import java.security.KeyPair;

/**
 * Wrapper class for the identity information relevant to <b>MY SELF</b> in the provisioning protocol
 */
public class MyIdentityMaterial implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private KeyPair identityKeyPair;
    private X509Crl identityCrl;
    private ProvisioningIdentityCertificate identityCertificate;

    public MyIdentityMaterial(KeyPair identityKeyPair, X509Crl identityCrl, ProvisioningIdentityCertificate identityCertificate) {
        this.identityKeyPair = identityKeyPair;
        this.identityCrl = identityCrl;
        this.identityCertificate = identityCertificate;
    }

    public KeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    public X509Crl getIdentityCrl() {
        return identityCrl;
    }

    public ProvisioningIdentityCertificate getIdentityCertificate() {
        return identityCertificate;
    }
}
