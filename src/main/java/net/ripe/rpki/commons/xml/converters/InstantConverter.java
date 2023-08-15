package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.SingleValueConverter;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.ResolverStyle;

import static java.time.temporal.ChronoField.HOUR_OF_DAY;
import static java.time.temporal.ChronoField.MILLI_OF_SECOND;
import static java.time.temporal.ChronoField.MINUTE_OF_HOUR;
import static java.time.temporal.ChronoField.SECOND_OF_MINUTE;


public class InstantConverter implements SingleValueConverter {

    private static final DateTimeFormatter FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE = new DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(DateTimeFormatter.ISO_LOCAL_DATE)
        .appendLiteral('T')
        .appendValue(HOUR_OF_DAY, 2)
        .appendLiteral(':')
        .appendValue(MINUTE_OF_HOUR, 2)
        .appendLiteral(':')
        .appendValue(SECOND_OF_MINUTE, 2)
        .appendLiteral('.')
        .appendValue(MILLI_OF_SECOND, 3)
        .appendOffsetId()
        .toFormatter()
        .withResolverStyle(ResolverStyle.STRICT);

    private static final DateTimeFormatter FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE = new DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(DateTimeFormatter.ISO_LOCAL_DATE)
        .appendLiteral('T')
        .appendValue(HOUR_OF_DAY, 2)
        .appendLiteral(':')
        .appendValue(MINUTE_OF_HOUR, 2)
        .appendLiteral(':')
        .appendValue(SECOND_OF_MINUTE, 2)
        .appendOffsetId()
        .toFormatter()
        .withResolverStyle(ResolverStyle.STRICT);

    private boolean useMillis = false;

    public InstantConverter() {
    }

    public InstantConverter(boolean useMillis) {
        this.useMillis = useMillis;
    }

    @Override
    public boolean canConvert(Class type) {
        return Instant.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return DateTimeFormatter.ISO_DATE_TIME.parse(s).query(Instant::from);
    }

    @Override
    public String toString(Object instant) {
        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant((Instant) instant, ZoneOffset.UTC);
        if (useMillis) {
            return FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE.format(zonedDateTime);
        } else {
            return FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE.format(zonedDateTime);
        }
    }
}
