package net.ripe.commons.certification.validation.fieldvalidators;

import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.DateTimeFormatterBuilder;

/**
 *  Controls the printing and parsing of a datetime to and from a string.
 *  This formatter is using the UTC timezone for printing and parsing objects.
 *  This class is a singleton and the formatter instance it returns is
 *  thread-safe and immutable.
 */
public final class UTCDateTimeFormatter {

    private static final int MIN_DIGITS_FOR_YEARS = 4;
    private static final int MAX_DIGITS_FOR_YEARS = 4;
    private static final int MIN_DIGITS_FOR_MONTH = 2;
    private static final int MIN_DIGITS_FOR_DAY = 2;
    private static final int MIN_DIGITS_FOR_HOUR = 2;
    private static final int MIN_DIGITS_FOR_MINUTE = 2;

    private static final DateTimeFormatter FORMATTER = new DateTimeFormatterBuilder()
    .appendYear(MIN_DIGITS_FOR_YEARS, MAX_DIGITS_FOR_YEARS).appendLiteral('-').appendMonthOfYear(MIN_DIGITS_FOR_MONTH)
    .appendLiteral('-').appendDayOfMonth(MIN_DIGITS_FOR_DAY)
    .appendLiteral(' ').appendHourOfDay(MIN_DIGITS_FOR_HOUR)
    .appendLiteral(':').appendMinuteOfHour(MIN_DIGITS_FOR_MINUTE)
    .toFormatter().withZone(DateTimeZone.UTC);

    private UTCDateTimeFormatter() {
    }

    public static DateTimeFormatter getInstance() {
        return FORMATTER;
    }
}
