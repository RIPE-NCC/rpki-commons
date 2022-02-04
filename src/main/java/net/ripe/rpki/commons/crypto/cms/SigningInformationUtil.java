package net.ripe.rpki.commons.crypto.cms;

import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.SignerInformation;
import org.joda.time.DateTime;
import org.joda.time.Instant;

import java.util.Optional;
import java.util.function.Function;

import static net.ripe.rpki.commons.validation.ValidationString.*;

/**
 * Extract signing time or binary signing time.
 *
 * Extensively tested via the test cases in BBNCMSConformanceTest that test this with CMS that is parsed using this
 * utility.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SigningInformationUtil {
    /**
     * Extract signing time from the signer information.
     *
     * Signing time is either provided in the signing-time [RFC5652] or binary-signing-time [RFC6019]
     * attribute, or neither. As stated in RFC 6019 Section 4 [Security Considerations] "only one
     * of these attributes SHOULD be present". [..] "However, if both of these attributes are present,
     * they MUST provide the same date and time."
     */
    public static SigningTimeResult extractSigningTime(ValidationResult validationResult, SignerInformation signer) {
        ImmutablePair<DateTime, Boolean> signingTime = extractTime(
                validationResult, CMSAttributes.signingTime, ONLY_ONE_SIGNING_TIME_ATTR, signer,
                attrValue -> UTC.dateTime(Time.getInstance(attrValue).getDate().getTime())
                );
        // Bouncy castle does not support https://datatracker.ietf.org/doc/html/rfc6019 binary signing time
        // parsing, which is the number of seconds since the unix epoch.
        ImmutablePair<DateTime, Boolean> binarySigningTime = extractTime(
                validationResult, CMSAttributes.binarySigningTime, ONLY_ONE_BINARY_SIGNING_TIME_ATTR, signer,
                attrValue -> UTC.dateTime(Instant.ofEpochSecond(ASN1Integer.getInstance(attrValue).getValue().longValueExact())));
        boolean valid = signingTime.right && binarySigningTime.right;

        if (signingTime.left != null && binarySigningTime.left != null) {
            valid = validationResult.rejectIfFalse(signingTime.left.equals(binarySigningTime.left), SIGNING_TIME_MUST_EQUAL_BINARY_SIGNING_TIME) && valid;
        }

        if (valid) {
            return new SigningTimeResult(signingTime.left != null ? signingTime.left : binarySigningTime.left);
        }
        return new SigningTimeResult(valid);
    }

    private static ImmutablePair<DateTime, Boolean> extractTime(ValidationResult validationResult, ASN1ObjectIdentifier identifier, String onlyOneValidationKey, SignerInformation signer, Function<ASN1Encodable, DateTime> timeExtractor) {
        // Do not use AttributeSet, this would deduplicate.
        ASN1EncodableVector signingTimeAttributes = signer.getSignedAttributes().getAll(identifier);
        if (signingTimeAttributes.size() == 0) {
            return ImmutablePair.of(null, true);
        }

        // https://datatracker.ietf.org/doc/html/rfc6019#section-3
        // The SignedAttributes MUST NOT include multiple instances of [either type of time attribute]
        if (!validationResult.rejectIfFalse(signingTimeAttributes.size() == 1, onlyOneValidationKey)) {
            return ImmutablePair.of(null, false);
        }

        final ASN1Encodable[] signingTimeValues = Attribute.getInstance(signingTimeAttributes.get(0)).getAttributeValues();
        // Both signingTime and binarySigningTime require <i>exactly</i> one value in the ASN.1 - e.g. not a set.
        if (!validationResult.rejectIfFalse(signingTimeValues.length == 1, SIGNING_TIME_ATTR_ONE_VALUE)) {
            return ImmutablePair.of(null, false);
        }

        return ImmutablePair.of(timeExtractor.apply(signingTimeValues[0]), true);
    }

    @Data
    public static class SigningTimeResult {
        /** The value of the signing time. */
        public final Optional<DateTime> signingTime;
        /**
         * Whether the signing time attribute was valid.
         * A SigningTime can not be invalid <b>and</b> have a value.
         */
        public final boolean valid;

        public SigningTimeResult(boolean valid) {
            this.valid = valid;
            this.signingTime = Optional.empty();
        }

        public SigningTimeResult(DateTime signingTime) {
            this.signingTime = Optional.ofNullable(signingTime);
            this.valid = true;
        }
    }
}
