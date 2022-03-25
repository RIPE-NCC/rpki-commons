package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import lombok.EqualsAndHashCode;
import lombok.Value;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateValidator;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.net.URI;
import java.security.Provider;
import java.util.Objects;
import java.util.Optional;

/**
 * See https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile-07.
 */
@Value
@EqualsAndHashCode(callSuper = true)
public class ASProviderAttestationCms extends RpkiSignedObject {

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
    Asn customerAsn;

    /**
     * The providerASSET contains the sequence (set) of AS numbers that are
     * authorized to further propagate announcements in the specified
     * address family received from the customer.
     */
    ImmutableSortedSet<ProviderAS> providerASSet;

    public ASProviderAttestationCms(RpkiSignedObjectInfo cmsObjectData, int version, Asn customerAsn, ImmutableSortedSet<ProviderAS> providerASSet) {
        super(cmsObjectData);
        Validate.isTrue(version == 0, "version must be 0");
        this.version = version;
        this.customerAsn = Objects.requireNonNull(customerAsn);
        this.providerASSet = Objects.requireNonNull(providerASSet);
    }

    @Override
    protected void validateWithCrl(String location, CertificateRepositoryObjectValidationContext context, ValidationOptions options, ValidationResult result, X509Crl crl) {
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateStrictValidator(context, options, result, crl);
        validator.validate(location, getCertificate());
    }

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }
}
