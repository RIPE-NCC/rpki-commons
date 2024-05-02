package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.base.Joiner;
import com.google.common.collect.Comparators;
import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.asn1.*;

import javax.annotation.CheckForNull;
import java.util.Comparator;
import java.util.List;
import java.util.stream.StreamSupport;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;
import static net.ripe.rpki.commons.validation.ValidationString.ASPA_CUSTOMER_ASN_NOT_IN_PROVIDER_ASNS;

public class AspaCmsParser extends RpkiSignedObjectParser {

    private int version;

    @CheckForNull
    private Asn customerAsn;
    private ImmutableSortedSet<Asn> providerASSet = ImmutableSortedSet.of();

    @Override
    public void parse(ValidationResult result, byte[] encoded) {
        super.parse(result, encoded);
        validateAspa();
    }

    public AspaCms getAspa() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("ASPA record validation failed: " + getValidationResult().getFailuresForCurrentLocation());
        }
        RpkiSignedObjectInfo cmsObjectData = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        return new AspaCms(cmsObjectData, version, customerAsn, providerASSet);
    }

    public boolean isSuccess() {
        return !getValidationResult().hasFailureForCurrentLocation();
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

        X509ResourceCertificate resourceCertificate = getCertificate();
        if (customerAsn != null) {
            // Do not reject for customer ASN not being certified if parsing failed earlier.
            validationResult.rejectIfFalse(
                            resourceCertificate != null &&
                            resourceCertificate.containsResources(new IpResourceSet(customerAsn)),
                    ValidationString.ASPA_CUSTOMER_ASN_CERTIFIED
            );

            // *  The CustomerASID value MUST NOT appear in any providerASID field
            validationResult.rejectIfTrue(providerASSet.contains(customerAsn), ASPA_CUSTOMER_ASN_NOT_IN_PROVIDER_ASNS, String.valueOf(customerAsn), Joiner.on(", ").join(providerASSet));
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
            if (maybeVersion instanceof DLTaggedObject) {
                // Version is optional and defaults to 0 if missing. An explicitly tagged integer is present when
                // another version is present.
                decodeVersion(validationResult, (DLTaggedObject) maybeVersion);

                ++index;
            } else {
                // Other pass/fails for same key are in `decodeVersion`
                validationResult.rejectIfFalse(false, ValidationString.ASPA_VERSION, "0 [missing]");
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

            List<Asn> providerAsList = StreamSupport.stream(providerAsnsSequence.spliterator(), false)
                .map(this::parseProviderAsn)
                .toList();

            //  * The elements of providers MUST be ordered in ascending numerical
            //    order.¶
            validationResult.rejectIfFalse(Comparators.isInStrictOrder(providerAsList, Comparator.naturalOrder()), ValidationString.ASPA_PROVIDER_AS_SET_VALID, "elements are in order");

            if (validationResult.hasFailureForCurrentLocation()) {
                return;
            }

            this.providerASSet = ImmutableSortedSet.copyOf(providerAsList);
            //  *  Each value of providerASID MUST be unique (with respect to the
            //     other elements of providers).
            validationResult.rejectIfFalse(providerASSet.size() == providerAsnsSequence.size(), ValidationString.ASPA_PROVIDER_AS_SET_VALID, "elements are unique");
            validationResult.rejectIfTrue(providerASSet.isEmpty(), ValidationString.ASPA_PROVIDER_AS_SET_NOT_EMPTY);
        } catch (IllegalArgumentException ex) {
            validationResult.error(ValidationString.ASPA_CONTENT_STRUCTURE);
        }
    }

    private void decodeVersion(ValidationResult validationResult, DLTaggedObject tagged) {
        validationResult.rejectIfFalse(tagged.getTagNo() == 0, ValidationString.ASPA_CONTENT_STRUCTURE);
        try {
            this.version = expect(tagged.getBaseObject(), ASN1Integer.class).intValueExact();
            validationResult.rejectIfFalse(this.version == 1, ValidationString.ASPA_VERSION, String.valueOf(this.version));
        } catch (ArithmeticException e) {
            validationResult.error(ValidationString.ASPA_VERSION, "out-of-bounds");
        }
    }

    private Asn parseProviderAsn(ASN1Encodable asn1Encodable) {
        return Asn1Util.parseAsId(expect(asn1Encodable, ASN1Integer.class));
    }
}
