package net.ripe.rpki.commons.crypto;

import org.apache.commons.lang3.Validate;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.Date;

/**
 * Validity period used by the certification system. Since certificates only
 * have up-to second accuracy with validity fields, this class truncates not
 * before and not after to second accuracy.
 */
public record ValidityPeriod(@NotNull Instant notValidBefore, @NotNull Instant notValidAfter) {
    public ValidityPeriod(@NotNull Instant notValidBefore, @NotNull Instant notValidAfter) {
        this.notValidBefore = truncatedMillis(notValidBefore);
        this.notValidAfter = truncatedMillis(notValidAfter);
        Validate.isTrue(!this.notValidAfter.isBefore(this.notValidBefore), "Got an invalid validity time from: " + notValidBefore + " to: " + notValidAfter);
    }

    public ValidityPeriod(@NotNull Date notValidBefore, @NotNull Date notValidAfter) {
        this(Instant.ofEpochMilli(notValidBefore.getTime()), Instant.ofEpochMilli(notValidAfter.getTime()));
    }

    public ValidityPeriod(@NotNull TemporalAccessor notValidBefore, @NotNull TemporalAccessor notValidAfter) {
        this(Instant.from(notValidBefore), Instant.from(notValidAfter));
    }

    public static ValidityPeriod of(@NotNull OffsetDateTime notValidBefore, @NotNull Period period) {
        return new ValidityPeriod(notValidBefore, notValidBefore.plus(period));
    }

    private static boolean isDateOrderingValid(Instant notValidBefore, Instant notValidAfter) {
        return !notValidAfter.isBefore(notValidBefore);
    }

    // Match resolution of certificate validity period (seconds)
    private Instant truncatedMillis(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS);
    }

    public ValidityPeriod withNotValidBefore(Instant notValidBefore) {
        return new ValidityPeriod(notValidBefore, notValidAfter());
    }

    public ValidityPeriod withNotValidAfter(Instant notValidAfter) {
        return new ValidityPeriod(notValidBefore(), notValidAfter);
    }

    public boolean contains(ValidityPeriod other) {
        return isValidAt(other.notValidBefore()) && isValidAt(other.notValidAfter());
    }

    public boolean isExpiredAt(@NotNull Instant instant) {
        return instant.isAfter(notValidAfter());
    }

    public boolean isValidAt(@NotNull Instant instant) {
        return !instant.isBefore(notValidBefore()) && !instant.isAfter(notValidAfter());
    }

    /**
     * Calculates the intersection of two validity periods.
     *
     * @param other the validity period to intersect with.
     * @return the intersection of this and the other validity period, or null
     *         if there is no overlap.
     */
    public @Nullable ValidityPeriod intersectedWith(@NotNull ValidityPeriod other) {
        Instant latestNotValidBefore = latestDateTimeOf(notValidBefore, other.notValidBefore);
        Instant earliestNotValidAfter = earliestDateTimeOf(notValidAfter, other.notValidAfter);
        if (isDateOrderingValid(latestNotValidBefore, earliestNotValidAfter)) {
            return new ValidityPeriod(latestNotValidBefore, earliestNotValidAfter);
        } else {
            // we got disjoint time intervals
            return null;
        }
    }

    private Instant earliestDateTimeOf(Instant date1, Instant date2) {
        return date1.isBefore(date2) ? date1 : date2;
    }

    private Instant latestDateTimeOf(Instant date1, Instant date2) {
        return date1.isAfter(date2) ? date1 : date2;
    }

    @Override
    public String toString() {
        return notValidBefore() + " - " + notValidAfter();
    }
}
