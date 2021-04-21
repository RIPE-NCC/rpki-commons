/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.joda.time.DateTime;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Map;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;

/**
 * @See {@link http://tools.ietf.org/html/draft-ietf-sidr-rpki-manifests-07}
 */

public class ManifestCmsParser extends RpkiSignedObjectParser {

    private int version = ManifestCms.DEFAULT_VERSION;

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
            thisUpdateTime = UTC.dateTime(expect(seq.getObjectAt(offset++), ASN1GeneralizedTime.class).getDate().getTime());
            nextUpdateTime = UTC.dateTime(expect(seq.getObjectAt(offset++), ASN1GeneralizedTime.class).getDate().getTime());
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
