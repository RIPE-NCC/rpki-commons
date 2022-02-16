package net.ripe.rpki.commons.provisioning.identity;

import lombok.Value;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;

import java.util.Optional;
import java.util.UUID;

/**
 * See RFC8183 section 5.2.3:
 *
 * "publisher's BPKI identity, a self-signed X.509 BPKI certificate.
 *  This certificate is the issuer of the BPKI EE certificates
 *  corresponding to private keys that the publisher will use to sign
 *  publication protocol messages to the repository."
 */
@Value
public class PublisherRequest {

    public static final int VERSION = 1;

    String handle;
    ProvisioningIdentityCertificate identityCertificate;
    Optional<Referral> referral;
    /**
     * Create a publisher identity to offer to your parent with a random UUID based handle.
     */
    public PublisherRequest(ProvisioningIdentityCertificate identityCertificate) {
        this(UUID.randomUUID().toString(), identityCertificate, Optional.empty());
    }

    /**
     * Create a child identity to offer to your parent, including a suggested handle. Note that
     * your parent may ignore this handle!
     */
    public PublisherRequest(String handle, ProvisioningIdentityCertificate identityCertificate, Optional<Referral> referral) {
        this.handle = handle;
        this.identityCertificate = identityCertificate;
        this.referral = referral;
    }

    public int getVersion() {
        return VERSION;
    }

    @Value
    public static class Referral {
        String referrer;
        byte[] authorizationToken;
    }

}
