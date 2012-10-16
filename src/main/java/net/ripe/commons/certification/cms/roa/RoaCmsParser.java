/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.cms.roa;

import static net.ripe.commons.certification.Asn1Util.*;
import static net.ripe.commons.certification.validation.ValidationString.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import net.ripe.commons.certification.Asn1Util;
import net.ripe.commons.certification.cms.RpkiSignedObjectInfo;
import net.ripe.commons.certification.cms.RpkiSignedObjectParser;
import net.ripe.commons.certification.rfc3779.AddressFamily;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

public class RoaCmsParser extends RpkiSignedObjectParser {

	private Asn asn;

	private List<RoaPrefix> prefixes = new ArrayList<RoaPrefix>();


	public RoaCmsParser() {
		super();
	}

	public RoaCmsParser(ValidationResult result) {
		super(result);
	}

    @Override
    public void parse(ValidationLocation location, byte[] encoded) {
        super.parse(location, encoded);
        validateRoa();
    }

    public boolean isSuccess() {
        return !getValidationResult().hasFailureForCurrentLocation();
    }

    public RoaCms getRoaCms() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("ROA validation failed");
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

	RoaPrefix parseRoaIpAddressFamily(IpResourceType type, DEREncodable der) {
		expect(der, DERSequence.class);
		DERSequence seq = (DERSequence) der;
		ValidationResult validationResult = getValidationResult();
		if (!validationResult.rejectIfFalse((seq.size() > 0) && (seq.size() <= 2), PREFIX_IN_ADDR_FAMILY)) {
			throw new IllegalArgumentException("ip address family sequence length invalid");
		}
		IpRange prefix = parseIpAddressAsPrefix(type, seq.getObjectAt(0));
		BigInteger maxLength = null;
		if (seq.size() > 1) {
			expect(seq.getObjectAt(1), DERInteger.class);
			maxLength = ((DERInteger) seq.getObjectAt(1)).getValue();
			if (!validationResult.rejectIfFalse((maxLength.compareTo(BigInteger.ZERO) >= 0) && (maxLength.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) <= 0), PREFIX_LENGTH)) {
				throw new IllegalArgumentException("prefix max length invalid");
			}
		}
		return new RoaPrefix(prefix, maxLength == null ? null : maxLength.intValue());
	}

	void parseRouteOriginAttestation(DEREncodable der) {

		expect(der, DERSequence.class);
		DERSequence seq = (DERSequence) der;

		if (!getValidationResult().rejectIfTrue(seq.size() == 3, ROA_ATTESTATION_VERSION, seq.getObjectAt(0).toString())) {
			// eContent seems to contain non-standard version (default 0 is omitted in structure)
			return;
		}

		if (!getValidationResult().rejectIfFalse(seq.size() == 2, ASN_AND_PREFIXES_IN_DER_SEQ)) {
			return;
		}
		asn = Asn1Util.parseAsId(seq.getObjectAt(0));
		prefixes = parseRoaIpAddressFamilySequence(seq.getObjectAt(1));
	}

	void parseRoaIpAddressFamily(List<RoaPrefix> roaPrefixList, DEREncodable der) {
		expect(der, DERSequence.class);
		DERSequence seq = (DERSequence) der;
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
		expect(seq.getObjectAt(1), DERSequence.class);
		DERSequence addresses = (DERSequence) seq.getObjectAt(1);

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

	List<RoaPrefix> parseRoaIpAddressFamilySequence(DEREncodable der) {
		expect(der, DERSequence.class);
		DERSequence seq = (DERSequence) der;

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
	public void decodeContent(DEREncodable encoded) {
		parseRouteOriginAttestation(encoded);
	}

}

