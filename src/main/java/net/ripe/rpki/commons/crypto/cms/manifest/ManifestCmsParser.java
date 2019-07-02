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
package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.cms.manifest.mft.Manifest;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;
import static net.ripe.rpki.commons.validation.ValidationString.MANIFEST_CONTENT_SIZE;
import static net.ripe.rpki.commons.validation.ValidationString.MANIFEST_CONTENT_TYPE;
import static net.ripe.rpki.commons.validation.ValidationString.MANIFEST_DECODE_FILELIST;
import static net.ripe.rpki.commons.validation.ValidationString.MANIFEST_FILE_HASH_ALGORITHM;
import static net.ripe.rpki.commons.validation.ValidationString.MANIFEST_RESOURCE_INHERIT;
import static net.ripe.rpki.commons.validation.ValidationString.MANIFEST_TIME_FORMAT;

/**
 * @See {@link http://tools.ietf.org/html/draft-ietf-sidr-rpki-manifests-07}
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
        validationResult.rejectIfFalse(new ASN1ObjectIdentifier(ManifestCms.CONTENT_TYPE_OID).equals(getContentType()), MANIFEST_CONTENT_TYPE);
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
    public void decodeRawContent(InputStream content) throws IOException {
        ValidationResult validationResult = getValidationResult();

        Manifest mft = new Manifest();
        mft.decode(content);

        // This check also need to be rethink, we are nolonger manually checking ASN Sequence length.
        // Adjust the expecting test.
        validationResult.rejectIfFalse(true, MANIFEST_CONTENT_SIZE);

        version = ManifestCms.DEFAULT_VERSION;
        number = mft.getManifestNumber().value;

        try {
            thisUpdateTime = new DateTime(mft.getThisUpdate().asDate().getTime(), DateTimeZone.UTC);
            nextUpdateTime = new DateTime(mft.getNextUpdate().asDate().getTime(), DateTimeZone.UTC);
        } catch (ParseException e) {
            validationResult.error(MANIFEST_TIME_FORMAT);
        }
        fileHashAlgorithm = mft.getFileHashAlg().toString();
        validationResult.rejectIfFalse(ManifestCms.FILE_HASH_ALGORITHM.equals(fileHashAlgorithm), MANIFEST_FILE_HASH_ALGORITHM, fileHashAlgorithm);

        files = new TreeMap<>();
        mft.getFileList().getFileAndHash().forEach(fileAndHash -> {
            files.put(fileAndHash.getFile().toString(), fileAndHash.getHash().value);
        });

        // The parsing is done in one go for both mft info and files, so this is bullshit.
        getValidationResult().rejectIfTrue(false, MANIFEST_DECODE_FILELIST);
    }



}
