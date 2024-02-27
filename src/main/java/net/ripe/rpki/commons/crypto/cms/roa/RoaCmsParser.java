package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.IllegalAsn1StructureException;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public class RoaCmsParser extends RpkiSignedObjectParser {

    private Asn asn;

    private List<RoaPrefix> prefixes = new ArrayList<>();

    @Override
    public void parse(ValidationResult result, byte[] encoded) {
        super.parse(result, encoded);
        validateRoa();
    }

    public boolean isSuccess() {
        return !getValidationResult().hasFailureForCurrentLocation();
    }

    public RoaCms getRoaCms() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("ROA validation failed: " + getValidationResult().getFailuresForCurrentLocation());
        }

        RpkiSignedObjectInfo cmsObjectInfo = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        return new RoaCms(cmsObjectInfo, asn, prefixes);
    }

    private void validateRoa() {
        ValidationResult validationResult = getValidationResult();

        if (!validationResult.rejectIfFalse(getContentType() != null, ROA_CONTENT_TYPE)) {
            return;
        }
        if (!validationResult.rejectIfFalse(RoaCms.CONTENT_TYPE.equals(getContentType()), ROA_CONTENT_TYPE, getContentType().toString())) {
            return;
        }

        IpResourceSet roaPrefixes = new IpResourceSet();
        for (RoaPrefix prefix : Collections.unmodifiableList(prefixes)) {
            roaPrefixes.add(prefix.getPrefix());
        }
        try {
            validationResult.rejectIfFalse(getResourceCertificate().containsResources(roaPrefixes), ROA_RESOURCES);
        } catch (Exception e) {
            validationResult.rejectIfFalse(false, ROA_RESOURCES);
        }
    }

    RoaPrefix parseRoaIpAddressFamily(IpResourceType type, ASN1Encodable der) {
        expect(der, ASN1Sequence.class);
        ASN1Sequence seq = (ASN1Sequence) der;
        ValidationResult validationResult = getValidationResult();
        if (!validationResult.rejectIfFalse((seq.size() > 0) && (seq.size() <= 2), PREFIX_IN_ADDR_FAMILY)) {
            throw new IllegalArgumentException("ip address family sequence length invalid");
        }
        IpRange prefix = parseIpAddressAsPrefix(type, seq.getObjectAt(0));
        BigInteger maxLength = null;
        if (seq.size() > 1) {
            maxLength = expect(seq.getObjectAt(1), ASN1Integer.class).getValue();
            /**
             * Check for overflow of int32, further check (compared to prefix) is performed by
             * {@link RoaPrefix#RoaPrefix(IpRange, Integer)}
             */
            if (!validationResult.rejectIfFalse((maxLength.compareTo(BigInteger.ZERO) >= 0) && (maxLength.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) <= 0), PREFIX_LENGTH)) {
                throw new IllegalArgumentException("prefix max length invalid");
            }
        }
        return new RoaPrefix(prefix, maxLength == null ? null : maxLength.intValue());
    }

    void parseRouteOriginAttestation(ASN1Encodable der) {
        ValidationResult validationResult = getValidationResult();
        try {
            ASN1Sequence seq = expect(der, ASN1Sequence.class);

            final int itemCount = seq.size();
            if (itemCount == 3) {
                Optional<BigInteger> maybeVersion = getTaggedVersion(0, seq);
                maybeVersion.ifPresentOrElse(version -> {
                    if (validationResult.rejectIfFalse(BigInteger.ZERO.equals(version), ROA_ATTESTATION_VERSION, "attestation version must be 0, but is " + version)) {
                        asn = Asn1Util.parseAsId(seq.getObjectAt(1));
                        prefixes = parseRoaIpAddressFamilySequence(seq.getObjectAt(2));
                    }
                }, () -> {
                    validationResult.error(ROA_ATTESTATION_VERSION, "missing/not explicitly tagged");
                });
            } else if (itemCount == 2) {
                asn = Asn1Util.parseAsId(seq.getObjectAt(0));
                prefixes = parseRoaIpAddressFamilySequence(seq.getObjectAt(1));
            } else {
                validationResult.rejectIfFalse(false, ASN_AND_PREFIXES_IN_DER_SEQ);
            }
        } catch (IllegalArgumentException ex) {
            validationResult.error(ROA_CONTENT_STRUCTURE);
        }
    }

    void parseRoaIpAddressFamily(List<RoaPrefix> roaPrefixList, ASN1Encodable der) {
        expect(der, ASN1Sequence.class);
        ASN1Sequence seq = (ASN1Sequence) der;
        ValidationResult validationResult = getValidationResult();
        if (seq.size() != 2) {
            validationResult.rejectIfFalse(false, ADDR_FAMILY_AND_ADDR_IN_DER_SEQ);
            throw new IllegalArgumentException("ROA sequence does not contain address family and addresses");
        }
        AddressFamily addressFamily = AddressFamily.fromDer(seq.getObjectAt(0));
        if (!(addressFamily.equals(AddressFamily.IPV4) || addressFamily.equals(AddressFamily.IPV6))) {
            validationResult.rejectIfFalse(false, ADDR_FAMILY);
            throw new IllegalArgumentException("Address family is neither IPv4 nor IPv6");
        }
        expect(seq.getObjectAt(1), ASN1Sequence.class);
        ASN1Sequence addresses = (ASN1Sequence) seq.getObjectAt(1);

        for (int i = 0; i < addresses.size(); ++i) {
            RoaPrefix roaPrefix;
            try {
                roaPrefix = parseRoaIpAddressFamily(addressFamily.toIpResourceType(), addresses.getObjectAt(i));
            } catch (IllegalArgumentException e) {
                roaPrefix = null;
            }

            if (roaPrefix != null) {
                roaPrefixList.add(roaPrefix);
            }
        }
    }

    List<RoaPrefix> parseRoaIpAddressFamilySequence(ASN1Encodable der) {
        expect(der, ASN1Sequence.class);
        ASN1Sequence seq = (ASN1Sequence) der;

        List<RoaPrefix> roaPrefixList = new ArrayList<>();
        boolean errorOccured = false;
        for (int i = 0; i < seq.size(); ++i) {
            try {
                parseRoaIpAddressFamily(roaPrefixList, seq.getObjectAt(i));
            } catch (IllegalArgumentException e) {
                errorOccured = true;
            }
        }
        ValidationResult validationResult = getValidationResult();
        if (!errorOccured) {
            validationResult.rejectIfFalse(true, ADDR_FAMILY_AND_ADDR_IN_DER_SEQ);
            validationResult.rejectIfFalse(true, ADDR_FAMILY);
        }

        validationResult.rejectIfTrue(roaPrefixList.isEmpty(), ROA_PREFIX_LIST);
        return roaPrefixList;
    }

    @Override
    public void decodeAsn1Content(ASN1Encodable encoded) {
        parseRouteOriginAttestation(encoded);
    }

}

