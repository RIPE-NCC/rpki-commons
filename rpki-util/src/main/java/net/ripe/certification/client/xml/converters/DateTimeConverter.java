package net.ripe.certification.client.xml.converters;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

import com.thoughtworks.xstream.converters.SingleValueConverter;

public class DateTimeConverter implements SingleValueConverter {

    private static final DateTimeFormatter FORMATTER = ISODateTimeFormat.dateTime().withZone(DateTimeZone.UTC);

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return DateTime.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return FORMATTER.parseDateTime(s);
    }

    @Override
    public String toString(Object datetime) {
        return FORMATTER.print((DateTime) datetime);
    }
}