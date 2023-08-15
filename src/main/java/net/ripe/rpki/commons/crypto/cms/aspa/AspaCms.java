package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.Value;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.jetbrains.annotations.NotNull;

/**
 * See https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile-07.
 */
@Value
@EqualsAndHashCode(callSuper = true)
public class AspaCms extends RpkiSignedObject {

    /**
     * https://www.iana.org/assignments/rpki/rpki.xhtml
     */
    public static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.49");

    /**
     * The version number of the ASProviderAttestation MUST be v0.
     */
    int version;

    /**
     * The customerASID field contains the AS number of the Autonomous
     * System that authorizes an upstream providers (listed in the
     * providerASSET) to propagate prefixes in the specified address family
     * other ASes.
     */
    @NotNull
    Asn customerAsn;

    /**
     * The providerASSET contains the sequence (set) of AS numbers that are
     * authorized to further propagate announcements in the specified
     * address family received from the customer.
     */
    @NotNull
    ImmutableSortedSet<ProviderAS> providerASSet;

    public AspaCms(RpkiSignedObjectInfo cmsObjectData, int version, @NotNull Asn customerAsn, @NotNull ImmutableSortedSet<ProviderAS> providerASSet) {
        super(cmsObjectData);
        Validate.isTrue(version == 0, "version must be 0");
        this.version = version;
        this.customerAsn = customerAsn;
        this.providerASSet = providerASSet;
    }
}
