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
package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import com.github.mangstadt.vinnie.VObjectProperty;
import com.github.mangstadt.vinnie.io.Context;
import com.github.mangstadt.vinnie.io.SyntaxRules;
import com.github.mangstadt.vinnie.io.VObjectDataListener;
import com.github.mangstadt.vinnie.io.VObjectReader;
import com.github.mangstadt.vinnie.io.Warning;
import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.google.common.io.CharStreams;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class GhostbustersCmsParser extends RpkiSignedObjectParser {

    private String vCardPayload;

    @Override
    public void parse(ValidationResult result, byte[] encoded) {
        super.parse(result, encoded);
        validateGhostbusters();
    }

    @Override
    public void decodeRawContent(InputStream content) throws IOException {
        vCardPayload = CharStreams.toString(new InputStreamReader(content, Charsets.UTF_8));
    }

    protected void validateGhostbusters() {
        ValidationResult validationResult = getValidationResult();

        if (!validationResult.rejectIfFalse(getContentType() != null, ValidationString.GHOSTBUSTERS_RECORD_CONTENT_TYPE)) {
            return;
        }
        if (!validationResult.rejectIfFalse(GhostbustersCms.CONTENT_TYPE.equals(getContentType()), ValidationString.GHOSTBUSTERS_RECORD_CONTENT_TYPE, getContentType().toString())) {
            return;
        }
        if (!validationResult.rejectIfNull(vCardPayload, ValidationString.GHOSTBUSTERS_RECORD_SINGLE_VCARD)) {
            return;
        }

        try (Reader reader = new StringReader(vCardPayload)) {
            SyntaxRules syntaxRules = SyntaxRules.vcard();
            VObjectReader vObjectReader = new VObjectReader(reader, syntaxRules);
            VCardValidator validator = new VCardValidator(validationResult);
            vObjectReader.parse(validator);

            validationResult.rejectIfFalse(
                    validator.vCardBegin == 1 && validator.vCardEnd == 1,
                    ValidationString.GHOSTBUSTERS_RECORD_SINGLE_VCARD,
                    String.valueOf(validator.vCardBegin));
            if (validationResult.hasFailureForCurrentLocation()) {
                return;
            }

            validationResult.rejectIfFalse(
                    validator.properties.containsKey("FN") && !Strings.isNullOrEmpty(validator.properties.get("FN")),
                    ValidationString.GHOSTBUSTERS_RECORD_FN_PRESENT);

            validationResult.rejectIfFalse(
                validator.properties.containsKey("ADR") ||
                    validator.properties.containsKey("TEL") ||
                    validator.properties.containsKey("EMAIL"),
                ValidationString.GHOSTBUSTERS_RECORD_ADR_TEL_OR_EMAIL_PRESENT
            );
        } catch (IOException e) {
            validationResult.error(ValidationString.CMS_CONTENT_PARSING);
        }
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

    private static class VCardValidator implements VObjectDataListener {
        private static final Set<String> ALLOWED_PROPERTIES = Sets.newHashSet("FN", "ADR", "TEL", "EMAIL", "ORG", "N");

        private final ValidationResult validationResult;

        public int vCardBegin = 0;
        public int vCardEnd = 0;
        public Map<String, String> properties = new HashMap<>();

        private VCardValidator(ValidationResult validationResult) {
            this.validationResult = validationResult;
        }

        @Override
        public void onComponentBegin(String name, Context context) {
            ++vCardBegin;
        }

        @Override
        public void onComponentEnd(String name, Context context) {
            ++vCardEnd;
        }

        @Override
        public void onProperty(VObjectProperty property, Context context) {
            validationResult.rejectIfFalse(ALLOWED_PROPERTIES.contains(property.getName()), ValidationString.GHOSTBUSTERS_RECORD_SUPPORTED_PROPERTY, property.getName());
            properties.put(property.getName(), property.getValue());
        }

        @Override
        public void onVersion(String value, Context context) {
            validationResult.rejectIfFalse("3.0".equals(value) || "4.0".equals(value), ValidationString.GHOSTBUSTERS_RECORD_VCARD_VERSION, value);
        }

        @Override
        public void onWarning(Warning warning, VObjectProperty property, Exception thrown, Context context) {

        }
    }
}
