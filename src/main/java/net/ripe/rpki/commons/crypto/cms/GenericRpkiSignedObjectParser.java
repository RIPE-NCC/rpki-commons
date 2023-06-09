package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.crypto.cms.aspa.AspaCms;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.joda.time.DateTime;

import java.util.Optional;

import static net.ripe.rpki.commons.util.RepositoryObjectType.*;

public class GenericRpkiSignedObjectParser extends RpkiSignedObjectParser {
    public DateTime getSigningTime() {
        return super.getSigningTime();
    }

    public Optional<RepositoryObjectType> getRepositoryObjectType() {
        final ASN1ObjectIdentifier contentType = getContentType();
        if (AspaCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Aspa);
        } else if (RoaCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Roa);
        } else if (GhostbustersCms.CONTENT_TYPE.equals(contentType)) {
            return Optional.of(Gbr);
        }
        return Optional.empty();
    }
}
