package net.ripe.commons.certification.cms.roa;

import static net.ripe.commons.certification.Asn1Util.expect;
import static net.ripe.commons.certification.Asn1Util.parseIpAddressAsPrefix;
import static net.ripe.commons.certification.validation.ValidationString.ADDR_FAMILY;
import static net.ripe.commons.certification.validation.ValidationString.ADDR_FAMILY_AND_ADDR_IN_DER_SEQ;
import static net.ripe.commons.certification.validation.ValidationString.ASN_AND_PREFIXES_IN_DER_SEQ;
import static net.ripe.commons.certification.validation.ValidationString.PREFIX_IN_ADDR_FAMILY;
import static net.ripe.commons.certification.validation.ValidationString.PREFIX_LENGTH;
import static net.ripe.commons.certification.validation.ValidationString.ROA_CONTENT_TYPE;
import static net.ripe.commons.certification.validation.ValidationString.ROA_PREFIX_LIST;
import static net.ripe.commons.certification.validation.ValidationString.ROA_RESOURCES;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.ripe.commons.certification.Asn1Util;
import net.ripe.commons.certification.cms.RpkiSignedObjectInfo;
import net.ripe.commons.certification.cms.RpkiSignedObjectParser;
import net.ripe.commons.certification.rfc3779.AddressFamily;
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

	private List<RoaPrefix> prefixes;


	public RoaCmsParser() {
		super();
	}

	public RoaCmsParser(ValidationResult result) {
		super(result);
	}

	@Override
    public void parse(String location, byte[] encoded) {
		super.parse(location, encoded);
		validateRoa();
	}

	public RoaCms getRoaCms() {
		if (getValidationResult().hasFailures()) {
			throw new IllegalArgumentException("Roa validation failed");
		}

		RpkiSignedObjectInfo cmsObjectInfo = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        return new RoaCms(cmsObjectInfo, asn, prefixes);
	}

	private void validateRoa() {
		ValidationResult validationResult = getValidationResult();
        if (!validationResult.isTrue(RoaCms.CONTENT_TYPE.equals(getContentType()), ROA_CONTENT_TYPE)) {
			return;
		}

		IpResourceSet roaPrefixes = new IpResourceSet();
		for (RoaPrefix prefix : Collections.unmodifiableList(prefixes)) {
			roaPrefixes.add(prefix.getPrefix());
		}
		validationResult.isTrue(getResourceCertificate().getResources().contains(roaPrefixes), ROA_RESOURCES);
	}

	RoaPrefix parseRoaIpAddressFamily(IpResourceType type, DEREncodable der) {
		expect(der, DERSequence.class);
		DERSequence seq = (DERSequence) der;
		ValidationResult validationResult = getValidationResult();
		if (!validationResult.isTrue((seq.size() > 0) && (seq.size() <= 2), PREFIX_IN_ADDR_FAMILY)) {
			throw new IllegalArgumentException("ip address family sequence length invalid");
		}
		IpRange prefix = parseIpAddressAsPrefix(type, seq.getObjectAt(0));
		BigInteger maxLength = null;
		if (seq.size() > 1) {
			expect(seq.getObjectAt(1), DERInteger.class);
			maxLength = ((DERInteger) seq.getObjectAt(1)).getValue();
			if (!validationResult.isTrue((maxLength.compareTo(BigInteger.ZERO) >= 0) && (maxLength.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) <= 0), PREFIX_LENGTH)) {
				throw new IllegalArgumentException("prefix max length invalid");
			}
		}
		return new RoaPrefix(prefix, maxLength == null ? null : maxLength.intValue());
	}

	void parseRouteOriginAttestation(DEREncodable der) {
		expect(der, DERSequence.class);
		DERSequence seq = (DERSequence) der;
		if (!getValidationResult().isTrue(seq.size() == 2, ASN_AND_PREFIXES_IN_DER_SEQ)) {
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
			validationResult.isTrue(false, ADDR_FAMILY_AND_ADDR_IN_DER_SEQ);
			throw new IllegalArgumentException("ROA sequence does not contain address family and addresses");
		}
		AddressFamily addressFamily = AddressFamily.fromDer(seq.getObjectAt(0));
		if (!(addressFamily.equals(AddressFamily.IPV4) || addressFamily.equals(AddressFamily.IPV6))) {
			validationResult.isTrue(false, ADDR_FAMILY);
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
			validationResult.isTrue(true, ADDR_FAMILY_AND_ADDR_IN_DER_SEQ);
			validationResult.isTrue(true, ADDR_FAMILY);
		}

		validationResult.isTrue(roaPrefixList.size() > 0, ROA_PREFIX_LIST);
		return roaPrefixList;
	}

	@Override
	public void decodeContent(DEREncodable encoded) {
		parseRouteOriginAttestation(encoded);
	}
}

