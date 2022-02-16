package net.ripe.rpki.commons.provisioning.identity;

import lombok.Value;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/**
 * See RFC8183 section 5.2.4:
 *
 * "The &lt;repository_response/&gt; message is a repository's response to a
 *  publisher which has previously sent a &lt;publisher_request/&gt; message."
 */
@Value
public class RepositoryResponse {

    public static final int VERSION = 1;

    Optional<String> tag;
    URI serviceUri;
    String publisherHandle;
    URI siaBase;
    Optional<URI> rrdpNotificationUri;
    ProvisioningIdentityCertificate repositoryBpkiTa;

    /**
     * Create a child identity to offer to your parent, including a suggested handle. Note that
     * your parent may ignore this handle!
     */
    public RepositoryResponse(Optional<String> tag, URI serviceUri, String publisherHandle, URI siaBase,
                              Optional<URI> rrdpNotificationUri, ProvisioningIdentityCertificate repositoryBpkiTa) {
        this.tag = Objects.requireNonNull(tag, "tag must not be null");
        this.serviceUri = Objects.requireNonNull(serviceUri, "serviceUri must not be null");
        this.publisherHandle = Objects.requireNonNull(publisherHandle, "publisherHandle must not be null");
        this.siaBase = Objects.requireNonNull(siaBase, "siaBase must not be null");
        this.rrdpNotificationUri = Objects.requireNonNull(rrdpNotificationUri, "rrdpNotificationUri must not be null");
        this.repositoryBpkiTa = Objects.requireNonNull(repositoryBpkiTa, "repositoryBpkiTa must not be null");
    }

    public int getVersion() {
        return VERSION;
    }
}
