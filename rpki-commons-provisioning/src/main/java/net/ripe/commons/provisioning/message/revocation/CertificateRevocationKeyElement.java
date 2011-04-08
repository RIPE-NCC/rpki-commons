package net.ripe.commons.provisioning.message.revocation;

import java.security.PublicKey;

import net.ripe.commons.certification.util.KeyPairUtil;

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

    public CertificateRevocationKeyElement(String className, PublicKey publicKey) {
        this.className = className;
        this.publicKeyHash = KeyPairUtil.getEncodedKeyIdentifier(publicKey);
    }

    public String getClassName() {
        return className;
    }

    public String getPublicKeyHash() {
        return publicKeyHash;
    }
}
