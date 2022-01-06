package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.SingleValueConverter;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;


public class DateTimeConverter implements SingleValueConverter {

    private static final DateTimeFormatter FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE = ISODateTimeFormat.dateTime().withZone(DateTimeZone.UTC);

    private static final DateTimeFormatter FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE = ISODateTimeFormat.dateTimeNoMillis().withZone(DateTimeZone.UTC);

    private boolean useMillis = false;

    public DateTimeConverter() {
    }

    public DateTimeConverter(boolean useMillis) {
        this.useMillis = useMillis;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return DateTime.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        try {
            return FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE.parseDateTime(s);
        } catch (IllegalArgumentException e) {
            return FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE.parseDateTime(s);
        }
    }

    @Override
    public String toString(Object datetime) {
        // TODO: Test this! Was failing for me when running unit tests from different time zone
        DateTime dateTimeWithZone = ((DateTime) datetime).withZone(DateTimeZone.UTC);
        if (useMillis) {
            return FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE.print(dateTimeWithZone);
        } else {
            return FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE.print(dateTimeWithZone);
        }
    }
}
