package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.SingleValueConverter;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class JavaUtilTimestampConverter implements SingleValueConverter {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME.withZone(ZoneOffset.UTC);

    @Override
    public boolean canConvert(Class type) {
        return Timestamp.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return new Timestamp(FORMATTER.parse(s).query(Instant::from).toEpochMilli());
    }

    @Override
    public String toString(Object datetime) {
        return FORMATTER.format(((Timestamp) datetime).toInstant());
    }
}
