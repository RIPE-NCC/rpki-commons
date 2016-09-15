/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.google.common.io.InputSupplier;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;

import java.io.IOException;
import java.io.InputStream;

import static net.ripe.rpki.commons.validation.ValidationString.DECODE_CONTENT;

public class GhostbustersCmsParser extends RpkiSignedObjectParser {

    private String vCardPayload;

    @Override
    public void decodeContent(ASN1Encodable encoded) {
    }

    @Override
    protected void parseContent(CMSSignedDataParser sp) {
        final ValidationResult validationResult = getValidationResult();
        final CMSTypedStream signedContent = sp.getSignedContent();
        contentType = signedContent.getContentType();

        try {
            final InputSupplier<InputStream> supplier = new InputSupplier<InputStream>() {
                @Override
                public InputStream getInput() throws IOException {
                    return signedContent.getContentStream();
                }
            };
            vCardPayload = CharStreams.toString(CharStreams.newReaderSupplier(supplier, Charsets.US_ASCII));
        } catch (IOException e) {
            validationResult.rejectIfFalse(false, DECODE_CONTENT);
            return;
        }
        validationResult.rejectIfFalse(true, DECODE_CONTENT);
    }

    public GhostbustersCms getGhostbustersCms() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("Ghostbuster record validation failed: " + getValidationResult().getFailuresForCurrentLocation());
        }
        RpkiSignedObjectInfo cmsObjectData = new RpkiSignedObjectInfo(getEncoded(), getResourceCertificate(), getContentType(), getSigningTime());
        return new GhostbustersCms(cmsObjectData, vCardPayload);
    }

    public boolean isSuccess() {
        return !getValidationResult().hasFailureForCurrentLocation();
    }
}
