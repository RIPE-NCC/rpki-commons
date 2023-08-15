package net.ripe.rpki.commons.provisioning.identity;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.util.Optional;

/**
 * A child identity to offer to your parent, including a suggested handle. Note that
 * your parent may ignore this handle!
 * <p>
 * See RFC8183 section 5.2.4:
 * <p>
 * "The &lt;repository_response/&gt; message is a repository's response to a
 * publisher which has previously sent a &lt;publisher_request/&gt; message."
 */
public record RepositoryResponse(
    @NotNull Optional<String> tag,
    @NotNull URI serviceUri,
    @NotNull String publisherHandle,
    @NotNull URI siaBase,
    @NotNull Optional<URI> rrdpNotificationUri,
    @NotNull ProvisioningIdentityCertificate repositoryBpkiTa
) {
    public static final int VERSION = 1;

    public int getVersion() {
        return VERSION;
    }
}
