package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.cms.aspa.AspaCms;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.Optional;

import static net.ripe.rpki.commons.util.RepositoryObjectType.*;

public class GenericRpkiSignedObjectParser extends RpkiSignedObjectParser {
    public @Nullable Instant getSigningTime() {
        return super.getSigningTime();
    }

    public Optional<RepositoryObjectType> getRepositoryObjectType() {
        final ASN1ObjectIdentifier contentType = getContentType();
        if (AspaCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Aspa);
        } else if (GhostbustersCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Gbr);
        } else if (ManifestCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Manifest);
        } else if (RoaCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Roa);
        }
        return Optional.empty();
    }
}
