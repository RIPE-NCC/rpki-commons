package net.ripe.rpki.commons.provisioning.identity;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.util.EqualsSupport;

import java.net.URI;

public class ParentIdentity extends EqualsSupport {

    public static final int VERSION = 1;
    private final String childHandle;
    private final String parentHandle;
    private final URI upDownUrl;
    private final ProvisioningIdentityCertificate parentIdCertificate;


    public ParentIdentity(URI upDownUrl, String parentHandle,
                          String childHandle,
                          ProvisioningIdentityCertificate parentIdCertificate) {
        this.upDownUrl = upDownUrl;
        this.parentHandle = parentHandle;
        this.childHandle = childHandle;
        this.parentIdCertificate = parentIdCertificate;
    }

    public String getChildHandle() {
        return childHandle;
    }

    public String getParentHandle() {
        return parentHandle;
    }

    public ProvisioningIdentityCertificate getParentIdCertificate() {
        return parentIdCertificate;
    }

    public URI getUpDownUrl() {
        return upDownUrl;
    }

    public int getVersion() {
        return VERSION;
    }
}
