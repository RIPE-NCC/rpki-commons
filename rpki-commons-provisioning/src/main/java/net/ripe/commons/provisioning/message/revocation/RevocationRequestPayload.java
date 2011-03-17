package net.ripe.commons.provisioning.message.revocation;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamAsAttribute;

public class RevocationRequestPayload {
    @XStreamAlias("class_name")
    @XStreamAsAttribute
    private String className;

    @XStreamAsAttribute
    private String ski;

    public RevocationRequestPayload(String className, String ski) {
        this.className = className;
        this.ski = ski;
    }

    public String getClassName() {
        return className;
    }

    public String getSki() {
        return ski;
    }
}
