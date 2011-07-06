package net.ripe.commons.provisioning.identity;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

public interface ProvisioningSubjectNamingStrategy {

    X500Principal getCertificateSubject(PublicKey publicKey);

}
