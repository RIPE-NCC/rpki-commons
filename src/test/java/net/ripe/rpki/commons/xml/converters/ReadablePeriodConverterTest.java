package net.ripe.rpki.commons.xml.converters;

import org.joda.time.DateTime;
import org.joda.time.MutablePeriod;
import org.joda.time.Period;
import org.joda.time.ReadablePeriod;
import org.junit.Assert;
import org.junit.Test;


public class ReadablePeriodConverterTest {

    private ReadablePeriodConverter subject = new ReadablePeriodConverter();

    @Test
    public void shouldSupportPeriod() {
        Assert.assertTrue(subject.canConvert(ReadablePeriod.class));
        Assert.assertTrue(subject.canConvert(Period.class));
        Assert.assertTrue(subject.canConvert(MutablePeriod.class));
        Assert.assertFalse(subject.canConvert(DateTime.class));
    }

    @Test
    public void shouldConvertToString() {
        Assert.assertEquals("P3M", subject.toString(Period.months(3)));
        Assert.assertEquals("P2Y3M7DT23H2M", subject.toString(Period.years(2).plusMonths(3).plusDays(7).plusHours(23).plusMinutes(2)));
    }

    @Test
    public void shouldConvertFromString() {
        Assert.assertTrue(subject.fromString("P3M") instanceof Period);
        Assert.assertEquals(Period.months(3), subject.fromString("P3M"));
        Assert.assertEquals(Period.years(2).plusMonths(3).plusDays(7).plusHours(23).plusMinutes(2), subject.fromString("P2Y3M7DT23H2M"));
    }

}
