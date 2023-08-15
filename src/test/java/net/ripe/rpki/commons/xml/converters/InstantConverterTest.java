package net.ripe.rpki.commons.xml.converters;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;


public class InstantConverterTest {


    private static final Instant START_EPOCH_DATE_TIME = Instant.ofEpochMilli(0);
    private static final String START_EPOCH_DATE_WITH_MILLIS_AND_ZONE = "1970-01-01T00:00:00.000Z";
    private static final String START_EPOCH_DATE_NO_MILLIS_AND_ZONE = "1970-01-01T00:00:00Z";

    private InstantConverter converter;

    @Before
    public void setUp() {
        converter = new InstantConverter();
    }

    @Test
    public void shouldConvertDateToStringWithoutMillisByDefault() {
        String dateStringFound = converter.toString(START_EPOCH_DATE_TIME);
        Assert.assertEquals(START_EPOCH_DATE_NO_MILLIS_AND_ZONE, dateStringFound);
    }

    @Test
    public void shouldConvertDateToStringWithMillisIfAsked() {
        converter = new InstantConverter(true);
        String dateStringFound = converter.toString(START_EPOCH_DATE_TIME);
        Assert.assertEquals(START_EPOCH_DATE_WITH_MILLIS_AND_ZONE, dateStringFound);
    }

    @Test
    public void shouldUnderstandDateStringWithMillis() {
        var dateFound = (Instant) converter.fromString(START_EPOCH_DATE_WITH_MILLIS_AND_ZONE);
        Assert.assertEquals(START_EPOCH_DATE_TIME, dateFound);
    }

    @Test
    public void shouldUnderstandIscDateFormat() {
        // i.e. without millis
        String iscDate = START_EPOCH_DATE_NO_MILLIS_AND_ZONE;

        var dateFound = (Instant) converter.fromString(iscDate);
        Assert.assertEquals(START_EPOCH_DATE_TIME, dateFound);
    }

}
