package net.ripe.commons.provisioning.payload.revocation;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;

public class CertificateRevocationKeyElement {
    
    @XStreamAlias("class_name")
    @XStreamAsAttribute
    private String className;

    // byte arrays are not allowed as attribute; hence we do the encoding ourselves
    @XStreamAlias("ski")
    @XStreamAsAttribute
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
