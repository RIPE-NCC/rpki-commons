package net.ripe.rpki.commons.crypto;

import net.ripe.rpki.commons.util.EqualsSupport;
import net.ripe.rpki.commons.util.UTC;
import org.apache.commons.lang3.Validate;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.joda.time.ReadableInstant;

import java.io.Serializable;
import java.util.Date;

/**
 * Validity period used by the certification system. Since certificates only
 * have up-to second accuracy with validity fields, this class truncates not
 * before and not after to second accuracy.
 */
public class ValidityPeriod extends EqualsSupport implements Serializable {
    private static final long serialVersionUID = 2L;

    private final DateTime notValidBefore;
    private final DateTime notValidAfter;

    public ValidityPeriod() {
        this((Date) null, (Date) null);
    }

    public ValidityPeriod(ReadableInstant notValidBefore, ReadableInstant notValidAfter) {
        this.notValidBefore = (notValidBefore == null) ? null : truncatedMillis(UTC.dateTime(notValidBefore));
        this.notValidAfter = (notValidAfter == null) ? null : truncatedMillis(UTC.dateTime(notValidAfter));
        Validate.isTrue(isDateOrderingValid(this.notValidBefore, this.notValidAfter), "Got an invalid validatity time from: " + notValidBefore + " to: " + notValidAfter);
    }

    public ValidityPeriod(Date notValidBefore, Date notValidAfter) {
        this.notValidBefore = (notValidBefore == null) ? null : truncatedMillis(UTC.dateTime(notValidBefore));
        this.notValidAfter = (notValidAfter == null) ? null : truncatedMillis(UTC.dateTime(notValidAfter));
        Validate.isTrue(isDateOrderingValid(this.notValidBefore, this.notValidAfter), "Got an invalid validatity time from: " + notValidBefore + " to: " + notValidAfter);
    }

    private static boolean isDateOrderingValid(DateTime notValidBefore, DateTime notValidAfter) {
        return (notValidBefore == null || notValidAfter == null || notValidBefore.isEqual(notValidAfter) || notValidBefore.isBefore(notValidAfter));
    }

    // Match resolution of certificate validity period (seconds)
    private DateTime truncatedMillis(DateTime dateTime) {
        return dateTime.withMillisOfSecond(0);
    }

    public DateTime getNotValidAfter() {
        return notValidAfter;
    }

    public DateTime getNotValidBefore() {
        return notValidBefore;
    }

    public ValidityPeriod withNotValidBefore(ReadableInstant notValidBefore) {
        return new ValidityPeriod(notValidBefore, getNotValidAfter());
    }

    public ValidityPeriod withNotValidAfter(ReadableInstant notValidAfter) {
        return new ValidityPeriod(getNotValidBefore(), notValidAfter);
    }

    public boolean contains(ValidityPeriod other) {
        return isValidAt(other.getNotValidBefore()) && isValidAt(other.getNotValidAfter());
    }

    public boolean isExpiredNow() {
        return isExpiredAt(new Instant());
    }

    public boolean isExpiredAt(ReadableInstant instant) {
        return notValidAfter != null && instant.isAfter(getNotValidAfter());
    }

    public boolean isValidNow() {
        return isValidAt(new Instant());
    }

    public boolean isValidAt(ReadableInstant instant) {
        if (instant == null) {
            return !isClosed();
        } else {
            return (notValidBefore == null || !instant.isBefore(getNotValidBefore()))
                    && (notValidAfter == null || !instant.isAfter(getNotValidAfter()));
        }
    }

    /**
     * @return true if this instances notValidBefore and notValidAfter are both
     *         specified.
     */
    public boolean isClosed() {
        return notValidBefore != null && notValidAfter != null;
    }

    /**
     * Calculates the intersection of two validity periods, taking into account
     * open-ended validity periods.
     *
     * @param other the validity period to intersect with.
     * @return the intersection of this and the other validity period, or null
     *         if there is no overlap.
     */
    public ValidityPeriod intersectedWith(ValidityPeriod other) {
        DateTime latestNotValidBefore = latestDateTimeOf(notValidBefore, other.notValidBefore);
        DateTime earliestNotValidAfter = earliestDateTimeOf(notValidAfter, other.notValidAfter);
        if (isDateOrderingValid(latestNotValidBefore, earliestNotValidAfter)) {
            return new ValidityPeriod(latestNotValidBefore, earliestNotValidAfter);
        } else {
            // we got disjoint time intervals
            return null;
        }
    }

    private DateTime earliestDateTimeOf(DateTime date1, DateTime date2) {
        if (date1 == null) {
            return date2;
        }
        if (date2 == null) {
            return date1;
        }
        return date1.isBefore(date2) ? date1 : date2;
    }

    private DateTime latestDateTimeOf(DateTime date1, DateTime date2) {
        if (date1 == null) {
            return date2;
        }
        if (date2 == null) {
            return date1;
        }
        return date1.isAfter(date2) ? date1 : date2;
    }

    @Override
    public String toString() {
        return getNotValidBefore() + " - " + getNotValidAfter();
    }
}
