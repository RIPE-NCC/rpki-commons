package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;

import javax.annotation.CheckForNull;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;
import static net.ripe.rpki.commons.validation.ValidationString.ASPA_CUSTOMER_ASN_NOT_IN_PROVIDER_ASNS;

public class AspaCmsParser extends RpkiSignedObjectParser<AspaCms> {

    private int version;

    @CheckForNull
    private Asn customerAsn;
    private ImmutableSortedSet<ProviderAS> providerASSet = ImmutableSortedSet.of();

    @Override
    public Optional<AspaCms> validateTypeSpecific(RpkiSignedObjectInfo info) {
        validateAspa();
        return getValidationResult().hasFailureForCurrentLocation() ? Optional.empty() : Optional.of(new AspaCms(info, version, customerAsn, providerASSet));
    }

    @Deprecated(forRemoval = true)
    public AspaCms getAspa() {
        return getResult().orElseThrow(
            () -> new IllegalArgumentException("ASPA record validation failed: " + getValidationResult().getFailuresForCurrentLocation())
        );
    }

    /**
     * See https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile-07#section-4.
     */
    private void validateAspa() {
        ValidationResult validationResult = getValidationResult();

        validationResult.rejectIfFalse(
            AspaCms.CONTENT_TYPE.equals(getContentType()),
            ValidationString.ASPA_CONTENT_TYPE,
            String.valueOf(getContentType())
        );

        X509ResourceCertificate resourceCertificate = getResourceCertificate();
        validationResult.rejectIfFalse(
                customerAsn != null &&
                        resourceCertificate != null &&
                        resourceCertificate.containsResources(new IpResourceSet(customerAsn)),
                ValidationString.ASPA_CUSTOMER_ASN_CERTIFIED
        );

        // *  The CustomerASID value MUST NOT appear in any providerASID field
        if (customerAsn != null) {
            boolean providerAsInCustomerAs = providerASSet.stream().map(ProviderAS::providerAsn).anyMatch(customerAsn::equals);
            validationResult.rejectIfTrue(providerAsInCustomerAs, ASPA_CUSTOMER_ASN_NOT_IN_PROVIDER_ASNS, String.valueOf(customerAsn), Joiner.on(", ").join(providerASSet));
        }
    }

    @Override
    public void decodeAsn1Content(ASN1Encodable content) {
        ValidationResult validationResult = getValidationResult();
        try {
            ASN1Sequence seq = expect(content, ASN1Sequence.class);

            final int itemCount = seq.size();
            if (itemCount < 2 || itemCount > 3) {
                validationResult.error(ValidationString.ASPA_CONTENT_STRUCTURE);
                return;
            }

            int index = 0;
            ASN1Encodable maybeVersion = seq.getObjectAt(index);
            if (maybeVersion instanceof DERTaggedObject) {
                // Version is optional and defaults to 0, so should not be explicitly encoded when using DER encoding
                // If it is present and correct, we still accept the object. If the version is different, reject the
                // object.
                decodeVersion(validationResult, (DERTaggedObject) maybeVersion);

                ++index;
            } else {
                this.version = 0;
            }

            validationResult.rejectIfFalse(index < itemCount && seq.getObjectAt(index) instanceof ASN1Integer, ValidationString.ASPA_CUSTOMER_ASN_PRESENT);
            if (validationResult.hasFailureForCurrentLocation()) {
                return;
            }

            this.customerAsn = Asn1Util.parseAsId(seq.getObjectAt(index));
            ++index;

            if (index >= itemCount) {
                validationResult.error(ValidationString.ASPA_CONTENT_STRUCTURE);
                return;
            }

            ASN1Sequence providerAsnsSequence = expect(seq.getObjectAt(index), ASN1Sequence.class);
            // TODO:
            //    *  The elements of providers MUST be ordered in ascending numerical
            //      order by the value of the providerASID field.
            //   *  Each value of providerASID MUST be unique (with respect to the
            //        other elements of providers).
            this.providerASSet = StreamSupport.stream(providerAsnsSequence.spliterator(), false)
                .map(this::parseProviderAS)
                .collect(ImmutableSortedSet.toImmutableSortedSet(Comparator.naturalOrder()));
            validationResult.rejectIfTrue(providerASSet.isEmpty(), ValidationString.ASPA_PROVIDER_AS_SET_NOT_EMPTY);
        } catch (IllegalArgumentException ex) {
            validationResult.error(ValidationString.ASPA_CONTENT_STRUCTURE);
        }
    }

    private void decodeVersion(ValidationResult validationResult, DERTaggedObject tagged) {
        validationResult.rejectIfFalse(tagged.getTagNo() == 0, ValidationString.ASPA_CONTENT_STRUCTURE);
        try {
            this.version = expect(tagged.getBaseObject(), ASN1Integer.class).intValueExact();
            validationResult.rejectIfFalse(this.version == 0, ValidationString.ASPA_VERSION, String.valueOf(this.version));
        } catch (ArithmeticException e) {
            validationResult.error(ValidationString.ASPA_VERSION, "out-of-bounds");
        }
    }

    private ProviderAS parseProviderAS(ASN1Encodable asn1Encodable) {
        ValidationResult validationResult = getValidationResult();
        ASN1Sequence sequence = expect(asn1Encodable, ASN1Sequence.class);

        validationResult.rejectIfTrue(sequence.size() < 1 || sequence.size() > 2, ValidationString.ASPA_PROVIDER_AS_SEQUENCE_SIZE);
        if (validationResult.hasFailureForCurrentLocation()) {
            throw new IllegalArgumentException("invalid sequence length");
        }

        Asn providerAsn = Asn1Util.parseAsId(sequence.getObjectAt(0));
        AddressFamily afiLimit = null;
        if (sequence.size() > 1) {
           afiLimit = AddressFamily.fromDer(sequence.getObjectAt(1));
           validationResult.rejectIfFalse(afiLimit.equals(AddressFamily.IPV4) || afiLimit.equals(AddressFamily.IPV6), ValidationString.ASPA_ADDR_FAMILY);
        }

        return new ProviderAS(providerAsn, Optional.ofNullable(afiLimit));
    }

}
