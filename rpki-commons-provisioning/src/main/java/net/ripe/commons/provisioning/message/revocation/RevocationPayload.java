package net.ripe.commons.provisioning.message.revocation;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;
import org.apache.commons.codec.binary.Base64;

public class RevocationPayload {
    @XStreamAlias("class_name")
    @XStreamAsAttribute
    private String className;

    // byte arrays are not allowed as attribute; hence we do the encoding ourselves
    @XStreamAlias("ski")
    @XStreamAsAttribute
    private String subjectKeyIdentifier;

    public RevocationPayload(String className, byte[] subjectKeyIdentifier) {
        this.className = className;
        this.subjectKeyIdentifier = Base64.encodeBase64URLSafeString(subjectKeyIdentifier);
    }

    public String getClassName() {
        return className;
    }

    public byte[] getSubjectKeyIdentifier() {
        return Base64.decodeBase64(subjectKeyIdentifier);
    }
}
