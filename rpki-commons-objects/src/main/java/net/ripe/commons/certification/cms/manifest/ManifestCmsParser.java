package net.ripe.commons.certification.cms.manifest;

import static net.ripe.commons.certification.Asn1Util.*;
import static net.ripe.commons.certification.validation.ValidationString.*;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

import net.ripe.commons.certification.cms.RpkiSignedObjectInfo;
import net.ripe.commons.certification.cms.RpkiSignedObjectParser;
import net.ripe.commons.certification.validation.ValidationResult;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

/**
 * See {@link http://tools.ietf.org/html/draft-ietf-sidr-rpki-manifests-07}
 */

public class ManifestCmsParser extends RpkiSignedObjectParser {

    private int version = ManifestCms.DEFAULT_VERSION;

    private static final int MANIFEST_CONTENT_SEQUENCE_LENGTH = 5;
    private static final int MANIFEST_NUMBER_INDEX = 0;
    private static final int THIS_UPDATE_TIME_INDEX = 1;
    private static final int NEXT_UPDATE_TIME_INDEX = 2;
    private static final int FILE_HASH_ALGORHYTHM_INDEX = 3;
	private static final int FILE_LIST_INDEX = 4;

	private BigInteger number;

	private DateTime thisUpdateTime;

    private DateTime nextUpdateTime;

    private String fileHashAlgorithm;

    private Map<String, byte[]> files;


	public ManifestCmsParser() {
		super();
	}

	public ManifestCmsParser(ValidationResult result) {
		super(result);
	}

	@Override
    public void parse(String location, byte[] encoded) {
		super.parse(location, encoded);
		validateManifest();
	}

	public ManifestCms getManifestCms() {
		ValidationResult validationResult = getValidationResult();
        if (validationResult.hasFailures()) {
			throw new IllegalArgumentException("Manifest validation failed: " + validationResult.getFailuresForCurrentLocation());
		}

        RpkiSignedObjectInfo cmsObjectData = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        ManifestCmsGeneralInfo manifestCmsGeneralInfo = new ManifestCmsGeneralInfo(version, number, thisUpdateTime, nextUpdateTime, fileHashAlgorithm);

		return new ManifestCms(cmsObjectData, manifestCmsGeneralInfo, files);
	}

	private void validateManifest() {
	    ValidationResult validationResult = getValidationResult();

	    if (!validationResult.isTrue(ManifestCms.CONTENT_TYPE.equals(getContentType()), MANIFEST_CONTENT_TYPE)) {
            return;
        }

        validationResult.isTrue(getResourceCertificate().isResourceSetInherited(), MANIFEST_RESOURCE_INHERIT);
    }

    void decodeManifest(DEREncodable encoded) {
        ValidationResult validationResult = getValidationResult();
        try {
            DERSequence seq = expect(encoded, DERSequence.class);
            if (!validationResult.isTrue(seq.size() == MANIFEST_CONTENT_SEQUENCE_LENGTH, MANIFEST_CONTENT_SIZE)) {
            	return;
            }
            version = ManifestCms.DEFAULT_VERSION;
            number = expect(seq.getObjectAt(MANIFEST_NUMBER_INDEX), DERInteger.class).getValue();
            // TODO use time zone from date.
            thisUpdateTime = new DateTime(expect(seq.getObjectAt(THIS_UPDATE_TIME_INDEX), DERGeneralizedTime.class).getDate().getTime(), DateTimeZone.UTC);
            nextUpdateTime = new DateTime(expect(seq.getObjectAt(NEXT_UPDATE_TIME_INDEX), DERGeneralizedTime.class).getDate().getTime(), DateTimeZone.UTC);
            fileHashAlgorithm = expect(seq.getObjectAt(FILE_HASH_ALGORHYTHM_INDEX), DERObjectIdentifier.class).getId();
            validationResult.isTrue(ManifestCms.FILE_HASH_ALGORITHM.equals(fileHashAlgorithm), MANIFEST_FILE_HASH_ALGORITHM, fileHashAlgorithm);
            files = new TreeMap<String, byte[]>();
            decodeFileList(files, seq.getObjectAt(FILE_LIST_INDEX));
        } catch (IllegalArgumentException e) {
            validationResult.isTrue(false, MANIFEST_CONTENT_STRUCTURE);
        } catch (ParseException e) {
            validationResult.isTrue(false, MANIFEST_TIME_FORMAT);
        }
    }

    void decodeFileAndHash(Map<String, byte[]> result, DEREncodable encoded) {
        DERSequence seq = expect(encoded, DERSequence.class);
        Validate.isTrue(seq.size() == 2, "der sequence does not contain file and hash");
        DERIA5String derFile = expect(seq.getObjectAt(0), DERIA5String.class);
        DERBitString derHash = expect(seq.getObjectAt(1), DERBitString.class);
        result.put(derFile.getString(), derHash.getBytes());
    }

    void decodeFileList(Map<String, byte[]> result, DEREncodable encoded) {
        DERSequence seq = expect(encoded, DERSequence.class);
        boolean errorOccured = false;
        for (int i = 0; i < seq.size(); ++i) {
        	try {
        		decodeFileAndHash(result, seq.getObjectAt(i));
        	} catch(IllegalArgumentException e) {
        		errorOccured = true;
        		break;
        	}
        }
        getValidationResult().isFalse(errorOccured, MANIFEST_DECODE_FILELIST);
    }

	@Override
	public void decodeContent(DEREncodable encoded) {
		decodeManifest(encoded);
	}
}
