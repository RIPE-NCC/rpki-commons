/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
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

import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public class RoaCmsParser extends RpkiSignedObjectParser {

    private Asn asn;

    private List<RoaPrefix> prefixes = new ArrayList<RoaPrefix>();

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
            validationResult.rejectIfFalse(getResourceCertificate().getResources().contains(roaPrefixes), ROA_RESOURCES);
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

            if (!validationResult.rejectIfTrue(seq.size() == 3, ROA_ATTESTATION_VERSION, seq.getObjectAt(0).toString())) {
                // eContent seems to contain non-standard version (default 0 is omitted in structure)
                return;
            }

            if (!validationResult.rejectIfFalse(seq.size() == 2, ASN_AND_PREFIXES_IN_DER_SEQ)) {
                return;
            }
            asn = Asn1Util.parseAsId(seq.getObjectAt(0));
            prefixes = parseRoaIpAddressFamilySequence(seq.getObjectAt(1));
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

        List<RoaPrefix> roaPrefixList = new ArrayList<RoaPrefix>();
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

        validationResult.rejectIfFalse(roaPrefixList.size() > 0, ROA_PREFIX_LIST);
        return roaPrefixList;
    }

    @Override
    public void decodeAsn1Content(ASN1Encodable encoded) {
        parseRouteOriginAttestation(encoded);
    }

}

