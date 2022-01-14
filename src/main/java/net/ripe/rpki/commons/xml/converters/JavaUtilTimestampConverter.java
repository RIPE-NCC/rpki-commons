package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.SingleValueConverter;
import net.ripe.rpki.commons.util.UTC;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

import java.sql.Timestamp;

public class JavaUtilTimestampConverter implements SingleValueConverter {

    private static final DateTimeFormatter FORMATTER = ISODateTimeFormat.dateTime().withZone(DateTimeZone.UTC);

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return Timestamp.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return new Timestamp(FORMATTER.parseDateTime(s).getMillis());
    }

    @Override
    public String toString(Object datetime) {
        return FORMATTER.print(UTC.dateTime(datetime));
    }
}
