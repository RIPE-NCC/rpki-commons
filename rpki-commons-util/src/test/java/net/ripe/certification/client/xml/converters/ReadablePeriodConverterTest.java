package net.ripe.certification.client.xml.converters;

import static org.junit.Assert.*;

import org.joda.time.DateTime;
import org.joda.time.MutablePeriod;
import org.joda.time.Period;
import org.joda.time.ReadablePeriod;
import org.junit.Test;


public class ReadablePeriodConverterTest {

    private ReadablePeriodConverter subject = new ReadablePeriodConverter();

    @Test
    public void shouldSupportPeriod() {
        assertTrue(subject.canConvert(ReadablePeriod.class));
        assertTrue(subject.canConvert(Period.class));
        assertTrue(subject.canConvert(MutablePeriod.class));
        assertFalse(subject.canConvert(DateTime.class));
    }

    @Test
    public void shouldConvertToString() {
        assertEquals("P3M", subject.toString(Period.months(3)));
        assertEquals("P2Y3M7DT23H2M", subject.toString(Period.years(2).plusMonths(3).plusDays(7).plusHours(23).plusMinutes(2)));
    }

    @Test
    public void shouldConvertFromString() {
        assertTrue(subject.fromString("P3M") instanceof Period);
        assertEquals(Period.months(3), subject.fromString("P3M"));
        assertEquals(Period.years(2).plusMonths(3).plusDays(7).plusHours(23).plusMinutes(2), subject.fromString("P2Y3M7DT23H2M"));
    }

}
