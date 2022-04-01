package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;

import java.util.Comparator;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;

public class AspaCmsParser extends RpkiSignedObjectParser {

    private int version;
    private AddressFamily afi;
    private Asn customerAsn;
    private ImmutableSortedSet<ProviderAS> providerASSet;

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

        validationResult.rejectIfFalse(
            customerAsn != null &&
                getCertificate().containsResources(new IpResourceSet(customerAsn)),
            ValidationString.ASPA_CUSTOMER_ASN_CERTIFIED
        );
    }

    @Override
    public void decodeAsn1Content(ASN1Encodable content) {
        ValidationResult validationResult = getValidationResult();
        try {
            ASN1Sequence seq = expect(content, ASN1Sequence.class);

            final int itemCount = seq.size();
            if (itemCount < 2) {
                validationResult.rejectIfFalse(false, ValidationString.ASPA_CONTENT_STRUCTURE);
                return;
            }

            int index = 0;
            ASN1Encodable maybeVersion = seq.getObjectAt(index);
            if (maybeVersion instanceof DERTaggedObject) {
                // Version is optional and defaults to 0, so should not be explicitly encoded when using DER encoding
                // If it is present and correct, we still accept the object. If the version is different, reject the
                // object.
                DERTaggedObject tagged = (DERTaggedObject) maybeVersion;
                validationResult.rejectIfFalse(tagged.getTagNo() == 0, ValidationString.ASPA_CONTENT_STRUCTURE);
                ASN1Integer version = expect(tagged.getBaseObject(), ASN1Integer.class);
                validationResult.rejectIfFalse(version.intValueExact() == 0, ValidationString.ASPA_VERSION, String.valueOf(version.intValueExact()));
                this.version = version.intValueExact();

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
                return;
            }

            ASN1Sequence providerAsnsSequence = expect(seq.getObjectAt(index), ASN1Sequence.class);
            this.providerASSet = StreamSupport.stream(providerAsnsSequence.spliterator(), false)
                .map(this::parseProviderAS)
                .collect(ImmutableSortedSet.toImmutableSortedSet(Comparator.naturalOrder()));
            validationResult.rejectIfTrue(providerASSet.isEmpty(), ValidationString.ASPA_PROVIDER_AS_SET_NOT_EMPTY);
        } catch (IllegalArgumentException ex) {
            validationResult.error(ValidationString.ASPA_CONTENT_STRUCTURE);
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
