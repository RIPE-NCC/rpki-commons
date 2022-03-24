package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

import java.util.Comparator;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;

public class ASProviderAttestationCmsParser extends RpkiSignedObjectParser {

    private static final String ASPA_CONTENT_SEQUENCE = "aspa.content.sequence";
    private static final String ASPA_CONTENT_STRUCTURE = "aspa.content.structure";
    private static final String ASPA_VERSION = "aspa.version";
    private static final String ASPA_ADDR_FAMILY = "aspa.address.family";
    private static final String ASPA_CUSTOMER_ASN_PRESENT = "aspa.customer.asn";
    private static final String ASPA_PROVIDER_ASNS_NOT_EMPTY = "aspa.provider.asns";
    private static final String ASPA_PROVIDER_AS_SEQUENCE = "aspa.provider.as.sequence";

    private int version;
    private AddressFamily afi;
    private Asn customerAsn;
    private ImmutableSortedSet<ProviderAS> providerASSet;

    @Override
    public void parse(ValidationResult result, byte[] encoded) {
        super.parse(result, encoded);
        //validateGhostbusters();
    }

    @Override
    public void decodeAsn1Content(ASN1Encodable content) {
        ValidationResult validationResult = getValidationResult();
        try {
            ASN1Sequence seq = expect(content, ASN1Sequence.class);

            final int itemCount = seq.size();
            if (itemCount < 2) {
                validationResult.rejectIfFalse(false, ASPA_CONTENT_SEQUENCE);
                return;
            }

            int index = 0;
            ASN1Encodable maybeVersion = seq.getObjectAt(index);
            if (maybeVersion instanceof DERTaggedObject) {
                DERTaggedObject tagged = (DERTaggedObject) maybeVersion;
                validationResult.rejectIfFalse(tagged.getTagNo() == 0, ASPA_VERSION, String.valueOf(tagged.getTagNo()));
                ASN1Integer version = expect(tagged.getBaseObject(), ASN1Integer.class);
                validationResult.rejectIfFalse(version.intValueExact() == 0, ASPA_VERSION, "attestation version must be 0, but is " + this.version);
                this.version = version.intValueExact();

                ++index;
            } else {
                this.version = 0;
            }

            validationResult.rejectIfFalse(index < itemCount && seq.getObjectAt(index) instanceof ASN1Integer, ASPA_CUSTOMER_ASN_PRESENT);
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
        } catch (IllegalArgumentException ex) {
            validationResult.error(ASPA_CONTENT_STRUCTURE);
        }
    }

    private ProviderAS parseProviderAS(ASN1Encodable asn1Encodable) {
        ValidationResult validationResult = getValidationResult();
        ASN1Sequence sequence = expect(asn1Encodable, ASN1Sequence.class);
    
        validationResult.rejectIfTrue(sequence.size() < 1 || sequence.size() > 2, ASPA_PROVIDER_AS_SEQUENCE);
        if (validationResult.hasFailureForCurrentLocation()) {
            throw new IllegalArgumentException("invalid sequence length");
        }

        Asn providerAsn = Asn1Util.parseAsId(sequence.getObjectAt(0));
        AddressFamily afiLimit = null;
        if (sequence.size() > 1) {
           afiLimit = AddressFamily.fromDer(sequence.getObjectAt(1));
           validationResult.rejectIfFalse(afiLimit.equals(AddressFamily.IPV4) || afiLimit.equals(AddressFamily.IPV6), ASPA_ADDR_FAMILY);
        }

        return new ProviderAS(providerAsn, Optional.ofNullable(afiLimit));
    }

    public ASProviderAttestationCms getASProviderAttestationCms() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("ASPA record validation failed: " + getValidationResult().getFailuresForCurrentLocation());
        }
        RpkiSignedObjectInfo cmsObjectData = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        return new ASProviderAttestationCms(cmsObjectData, version, customerAsn, providerASSet);
    }

    public boolean isSuccess() {
        return !getValidationResult().hasFailureForCurrentLocation();
    }

}
