package net.ripe.rpki.commons.xml.converters;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class DateTimeConverterTest {


    private static final DateTime START_EPOCH_DATE_TIME = new DateTime(0L).withZone(DateTimeZone.UTC);
    private static final String START_EPOCH_DATE_WITH_MILLIS_AND_ZONE = "1970-01-01T00:00:00.000Z";
    private static final String START_EPOCH_DATE_NO_MILLIS_AND_ZONE = "1970-01-01T00:00:00Z";

    private DateTimeConverter converter;

    @Before
    public void setUp() {
        converter = new DateTimeConverter();
    }

    @Test
    public void shouldConvertDateToStringWithoutMillisByDefault() {
        String dateStringFound = converter.toString(START_EPOCH_DATE_TIME);
        Assert.assertEquals(START_EPOCH_DATE_NO_MILLIS_AND_ZONE, dateStringFound);
    }

    @Test
    public void shouldConvertDateToStringWithMillisIfAsked() {
        converter = new DateTimeConverter(true);
        String dateStringFound = converter.toString(START_EPOCH_DATE_TIME);
        Assert.assertEquals(START_EPOCH_DATE_WITH_MILLIS_AND_ZONE, dateStringFound);
    }

    @Test
    public void shouldUnderstandDateStringWithMillis() {
        DateTime dateFound = (DateTime) converter.fromString(START_EPOCH_DATE_WITH_MILLIS_AND_ZONE);
        Assert.assertEquals(START_EPOCH_DATE_TIME, dateFound);
    }

    @Test
    public void shouldUnderstandIscDateFormat() {
        // i.e. without millis
        String iscDate = START_EPOCH_DATE_NO_MILLIS_AND_ZONE;

        DateTime dateFound = (DateTime) converter.fromString(iscDate);
        Assert.assertEquals(START_EPOCH_DATE_TIME, dateFound);
    }

}
