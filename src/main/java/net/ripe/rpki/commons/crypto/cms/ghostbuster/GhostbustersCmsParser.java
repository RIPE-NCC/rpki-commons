package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import com.google.common.io.CharStreams;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class GhostbustersCmsParser extends RpkiSignedObjectParser {

    private String vCardPayload;

    @Override
    public void parse(ValidationResult result, byte[] encoded) {
        super.parse(result, encoded);
        validateGhostbusters();
    }

    @Override
    public void decodeRawContent(InputStream content) throws IOException {
        vCardPayload = CharStreams.toString(new InputStreamReader(content, StandardCharsets.UTF_8));
    }

    protected void validateGhostbusters() {
        ValidationResult validationResult = getValidationResult();

        if (!validationResult.rejectIfFalse(getContentType() != null, ValidationString.GHOSTBUSTERS_RECORD_CONTENT_TYPE)) {
            return;
        }
        if (!validationResult.rejectIfFalse(GhostbustersCms.CONTENT_TYPE.equals(getContentType()), ValidationString.GHOSTBUSTERS_RECORD_CONTENT_TYPE, getContentType().toString())) {
            return;
        }

        if (!validationResult.rejectIfFalse(StringUtils.isNotBlank(vCardPayload), ValidationString.GHOSTBUSTERS_RECORD_SINGLE_VCARD)) {
            return;
        }

        if (!validationResult.rejectIfFalse(
                vCardPayload.startsWith("BEGIN:VCARD") &&
                        StringUtils.countMatches(vCardPayload, "BEGIN:VCARD") == 1,
                ValidationString.GHOSTBUSTERS_RECORD_SINGLE_VCARD)) {
            return;
        }

        if (!validationResult.rejectIfFalse(
                StringUtils.trim(vCardPayload).endsWith("END:VCARD") &&
                        StringUtils.countMatches(vCardPayload, "END:VCARD") == 1,
                ValidationString.GHOSTBUSTERS_RECORD_SINGLE_VCARD)) {
            return;
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

}
