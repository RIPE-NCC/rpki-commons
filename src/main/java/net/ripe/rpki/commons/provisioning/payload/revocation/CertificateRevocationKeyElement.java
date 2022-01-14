package net.ripe.rpki.commons.provisioning.payload.revocation;

import net.ripe.rpki.commons.util.EqualsSupport;

public class CertificateRevocationKeyElement extends EqualsSupport {

    private String className;

    // (XStream legacy) byte arrays are not allowed as attribute; hence we do the encoding ourselves
    private String publicKeyHash;

    public CertificateRevocationKeyElement(String className, String publicKeyHash) {
        this.className = className;
        this.publicKeyHash = publicKeyHash;
    }

    public String getClassName() {
        return className;
    }

    public String getPublicKeyHash() {
        return publicKeyHash;
    }
}
