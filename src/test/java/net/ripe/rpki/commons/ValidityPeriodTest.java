package net.ripe.rpki.commons;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.junit.Test;

import java.time.*;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.*;


public class ValidityPeriodTest {

    public final Clock clock = Clock.fixed(
        ZonedDateTime.of(2008, 4, 5, 0, 0, 0, 0, ZoneOffset.UTC).toInstant(),
        ZoneOffset.UTC
    );

    @Test
    public void testWrongValidityPeriod() {
        assertThatThrownBy(() -> {
            final Instant now = clock.instant();
            new ValidityPeriod(now, now.minusMillis(1));
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void singleInstantShouldBeOK() {
        var now = clock.instant();
        new ValidityPeriod(now, now);
    }

    @Test
    public void shouldSupportJavaUtilDate() {
        ValidityPeriod subject = new ValidityPeriod(new Date(), new Date());
        assertNotNull(subject.notValidBefore());
        assertNotNull(subject.notValidAfter());
    }

    @Test
    public void shouldTruncateToOneSecondAccuracy() {
        ValidityPeriod subject = new ValidityPeriod(
            ZonedDateTime.of(2008, 3, 30, 15, 44, 58, 943, ZoneOffset.UTC),
            ZonedDateTime.of(2008, 5, 30, 15, 44, 23, 123, ZoneOffset.UTC)
        );
        assertEquals(ZonedDateTime.of(2008, 3, 30, 15, 44, 58, 0, ZoneOffset.UTC).toInstant(), subject.notValidBefore());
        assertEquals(ZonedDateTime.of(2008, 5, 30, 15, 44, 23, 0, ZoneOffset.UTC).toInstant(), subject.notValidAfter());
    }

    @Test
    public void shouldSupportIntersection() {
        var t1 = ZonedDateTime.of(2008, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        var t2 = ZonedDateTime.of(2008, 2, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        var t3 = ZonedDateTime.of(2008, 11, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        var t4 = ZonedDateTime.of(2008, 12, 1, 0, 0, 0, 0, ZoneOffset.UTC);

        assertEquals(null, new ValidityPeriod(t1, t2).intersectedWith(new ValidityPeriod(t3, t4)));
        assertEquals(new ValidityPeriod(t2, t3), new ValidityPeriod(t1, t3).intersectedWith(new ValidityPeriod(t2, t4)));
        assertEquals(new ValidityPeriod(t2, t3), new ValidityPeriod(t2, t4).intersectedWith(new ValidityPeriod(t1, t3)));
        assertEquals(new ValidityPeriod(t1, t3), new ValidityPeriod(t1, t4).intersectedWith(new ValidityPeriod(t1, t3)));
        assertEquals(new ValidityPeriod(t2, t4), new ValidityPeriod(t2, t4).intersectedWith(new ValidityPeriod(t1, t4)));
    }

    @Test
    public void sameStartingInstantShouldBeValid() {
        ValidityPeriod validityPeriod = new ValidityPeriod(date(2008, 1, 1), date(2009, 1, 1));
        assertTrue(validityPeriod.isValidAt(date(2008, 1, 1)));
    }

    @Test
    public void sameEndingInstantShouldBeValid() {
        ValidityPeriod validityPeriod = new ValidityPeriod(date(2008, 1, 1), date(2009, 1, 1));
        assertTrue(validityPeriod.isValidAt(date(2009, 1, 1)));
    }

    @Test
    public void shouldBeValidWithinTheValidityPeriod() {
        ValidityPeriod validityPeriod = new ValidityPeriod(date(2008, 1, 1), date(2009, 1, 1));
        assertTrue(validityPeriod.isValidAt(date(2008, 6, 1)));
    }

    @Test
    public void shouldBeInvalidOutsideTheValidityPeriod() {
        ValidityPeriod validityPeriod = new ValidityPeriod(date(2007, 1, 1), date(2008, 1, 1));
        assertTrue(validityPeriod.isExpiredAt(Instant.now()));
        assertTrue(validityPeriod.isExpiredAt(date(2020, 1, 1)));
    }

    @Test
    public void truncatedMillisDates() {
        var instant = new Date(1502895557772L);

        final ValidityPeriod validityPeriod = new ValidityPeriod(instant, instant);

         assertEquals(validityPeriod.notValidBefore().toEpochMilli() % 1000, 0);
         assertEquals(validityPeriod.notValidAfter().toEpochMilli() % 1000, 0);
    }

    @Test
    public void truncatedMillisInstants() {
        var instant = Instant.ofEpochMilli(1502895557772L);

        final ValidityPeriod validityPeriod = new ValidityPeriod(instant, instant);

         assertEquals(validityPeriod.notValidBefore().toEpochMilli() % 1000, 0);
         assertEquals(validityPeriod.notValidAfter().toEpochMilli() % 1000, 0);
    }


    private Instant date(int year, int month, int day) {
        return LocalDate.of(year, month, day).atStartOfDay(ZoneOffset.UTC).toInstant();
    }
}
