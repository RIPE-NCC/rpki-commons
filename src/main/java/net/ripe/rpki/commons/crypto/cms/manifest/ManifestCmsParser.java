package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;
import static net.ripe.rpki.commons.validation.ValidationString.*;

/**
 * See {@see http://tools.ietf.org/html/draft-ietf-sidr-rpki-manifests-07}
 */

public class ManifestCmsParser extends RpkiSignedObjectParser {

    private int version = ManifestCms.DEFAULT_VERSION;

    private BigInteger number;

    private Instant thisUpdateTime;

    private Instant nextUpdateTime;

    private String fileHashAlgorithm;

    private Map<String, byte[]> files;

    @Override
    public void parse(ValidationResult result, byte[] encoded) {
        super.parse(result, encoded);
        if (isSuccess()) {
            validateManifest();
        }
    }

    public boolean isSuccess() {
        return !getValidationResult().hasFailures();
    }

    public ManifestCms getManifestCms() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("Manifest validation failed: " + getValidationResult().getFailuresForCurrentLocation());
        }

        RpkiSignedObjectInfo cmsObjectData = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        ManifestCmsGeneralInfo manifestCmsGeneralInfo = new ManifestCmsGeneralInfo(version, number, thisUpdateTime, nextUpdateTime, fileHashAlgorithm);
        return new ManifestCms(cmsObjectData, manifestCmsGeneralInfo, files);
    }

    private void validateManifest() {
        ValidationResult validationResult = getValidationResult();
        validationResult.rejectIfFalse(ManifestCms.CONTENT_TYPE.equals(getContentType()), MANIFEST_CONTENT_TYPE);
        // RFC 6486 section 5.1.2:
        // This EE certificate MUST describe its Internet Number Resources
        // (INRs) using the "inherit" attribute, rather than explicit
        // description of a resource set (see [RFC3779]).
        validationResult.rejectIfFalse(getResourceCertificate().isResourceSetInherited(), MANIFEST_RESOURCE_INHERIT);
    }

    void decodeFileAndHash(Map<String, byte[]> result, ASN1Encodable encoded) {
        ASN1Sequence seq = expect(encoded, ASN1Sequence.class);
        Validate.isTrue(seq.size() == 2, "der sequence does not contain file and hash");
        DERIA5String derFile = expect(seq.getObjectAt(0), DERIA5String.class);
        DERBitString derHash = expect(seq.getObjectAt(1), DERBitString.class);
        result.put(derFile.getString(), derHash.getBytes());
    }

    void decodeFileList(Map<String, byte[]> result, ASN1Encodable encoded) {
        ASN1Sequence seq = expect(encoded, ASN1Sequence.class);
        boolean errorOccured = false;
        for (int i = 0; i < seq.size(); ++i) {
            try {
                decodeFileAndHash(result, seq.getObjectAt(i));
            } catch (IllegalArgumentException e) {
                errorOccured = true;
                break;
            }
        }
        getValidationResult().rejectIfTrue(errorOccured, MANIFEST_DECODE_FILELIST);
    }

    @Override
    public void decodeAsn1Content(ASN1Encodable encoded) {
        ValidationResult validationResult = getValidationResult();
        try {
            ASN1Sequence seq = expect(encoded, ASN1Sequence.class);
            final int itemCount = seq.size();
            int offset = 0;
            if (itemCount == 6) {
                BigInteger version = getRpkiObjectVersion(seq);
                validationResult.rejectIfFalse(BigInteger.ZERO.equals(version), "mf.version", "manifest version must be 0, but is " + version);
                offset++;
            } else if (itemCount == 5) {
                version = ManifestCms.DEFAULT_VERSION;
            }

            validationResult.rejectIfFalse(itemCount == 5 || itemCount == 6, "mf.content.size");
            if (validationResult.hasFailureForCurrentLocation()) {
                return;
            }
            number = expect(seq.getObjectAt(offset++), ASN1Integer.class).getValue();
            thisUpdateTime = Instant.ofEpochMilli(expect(seq.getObjectAt(offset++), ASN1GeneralizedTime.class).getDate().getTime());
            nextUpdateTime = Instant.ofEpochMilli(expect(seq.getObjectAt(offset++), ASN1GeneralizedTime.class).getDate().getTime());
            fileHashAlgorithm = expect(seq.getObjectAt(offset++), ASN1ObjectIdentifier.class).getId();
            validationResult.rejectIfFalse(ManifestCms.FILE_HASH_ALGORITHM.equals(fileHashAlgorithm), MANIFEST_FILE_HASH_ALGORITHM, fileHashAlgorithm);
            files = new TreeMap<>();
            decodeFileList(files, seq.getObjectAt(offset));
        } catch (IllegalArgumentException e) {
            validationResult.error(MANIFEST_CONTENT_STRUCTURE);
        } catch (ParseException e) {
            validationResult.error(MANIFEST_TIME_FORMAT);
        }
    }

}
