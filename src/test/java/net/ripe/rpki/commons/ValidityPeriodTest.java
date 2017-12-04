/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.LocalDate;
import org.joda.time.Period;
import org.joda.time.ReadableInstant;
import org.junit.Rule;
import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class ValidityPeriodTest {

    @Rule
    public FixedDateRule fixedDateRule = new FixedDateRule(new DateTime(2008, 04, 05, 0, 0, 0, 0, DateTimeZone.UTC));


    @Test
    public void testWrongValidityPeriod() {
        try {
            new ValidityPeriod(new DateTime(), new DateTime().minus(Period.millis(1)));
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void singleInstantShouldBeOK() {
        DateTime now = new DateTime();
        new ValidityPeriod(now, now);
    }

    @Test
    public void shouldAllowUnspecifiedNotValidAfterDate() {
        ValidityPeriod closed = new ValidityPeriod(date(2008, 1, 1), date(2008, 12, 1));
        ValidityPeriod open = new ValidityPeriod(date(2008, 1, 1), null);

        assertTrue(closed.isClosed());
        assertFalse(open.isClosed());
        assertTrue("open should contain closed", open.contains(closed));
        assertFalse("closed should not contain open", closed.contains(open));
        assertTrue(open.isValidAt(date(2008, 1, 1)));
        assertTrue(open.isValidAt(date(2023, 1, 1)));
        assertFalse(open.isValidAt(date(2003, 1, 1)));
    }

    @Test
    public void shouldAllowUnspecifiedNotBeforeAfterDate() {
        ValidityPeriod closed = new ValidityPeriod(date(2008, 1, 1), date(2008, 12, 1));
        ValidityPeriod open = new ValidityPeriod(null, date(2008, 12, 1));

        assertTrue(closed.isClosed());
        assertFalse(open.isClosed());
        assertTrue("open should contain closed", open.contains(closed));
        assertFalse("closed should not contain open", closed.contains(open));
        assertTrue(open.isValidAt(date(2008, 1, 1)));
        assertFalse(open.isValidAt(date(2023, 1, 1)));
        assertTrue(open.isValidAt(date(2003, 1, 1)));
    }

    @Test
    public void shouldSupportJavaUtilDate() {
        ValidityPeriod subject = new ValidityPeriod(new Date(), new Date());
        assertNotNull(subject.getNotValidBefore());
        assertNotNull(subject.getNotValidAfter());

        subject = new ValidityPeriod(new Date(), null);
        assertNotNull(subject.getNotValidBefore());
        assertNull(subject.getNotValidAfter());

        subject = new ValidityPeriod(null, new Date());
        assertNull(subject.getNotValidBefore());
        assertNotNull(subject.getNotValidAfter());
    }

    @Test
    public void shouldTruncateToOneSecondAccuracy() {
        ValidityPeriod subject = new ValidityPeriod(new DateTime(2008, 3, 30, 15, 44, 58, 943, DateTimeZone.UTC), new DateTime(2008, 5, 30, 15, 44, 23, 123, DateTimeZone.UTC));
        assertEquals(new DateTime(2008, 3, 30, 15, 44, 58, 0, DateTimeZone.UTC), subject.getNotValidBefore());
        assertEquals(new DateTime(2008, 5, 30, 15, 44, 23, 0, DateTimeZone.UTC), subject.getNotValidAfter());
    }

    @Test
    public void shouldSupportIntersection() {
        DateTime t1 = new DateTime(2008, 1, 1, 0, 0, 0, 0);
        DateTime t2 = new DateTime(2008, 2, 1, 0, 0, 0, 0);
        DateTime t3 = new DateTime(2008, 11, 1, 0, 0, 0, 0);
        DateTime t4 = new DateTime(2008, 12, 1, 0, 0, 0, 0);

        assertEquals(null, new ValidityPeriod(t1, t2).intersectedWith(new ValidityPeriod(t3, t4)));
        assertEquals(new ValidityPeriod(), new ValidityPeriod().intersectedWith(new ValidityPeriod()));
        assertEquals(new ValidityPeriod(t1, t3), new ValidityPeriod(t1, t3).intersectedWith(new ValidityPeriod()));
        assertEquals(new ValidityPeriod(t1, t3), new ValidityPeriod().intersectedWith(new ValidityPeriod(t1, t3)));
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
        assertTrue(validityPeriod.isValidNow());
    }

    @Test
    public void shouldBeInvalidOutsideTheValidityPeriod() {
        ValidityPeriod validityPeriod = new ValidityPeriod(date(2007, 1, 1), date(2008, 1, 1));
        assertTrue(validityPeriod.isExpiredNow());
        assertTrue(validityPeriod.isExpiredAt(date(2020, 1, 1)));
    }

    @Test
    public void shouldNeverBeExpiredIfNotValidAfterIsNotDefined() {
        ValidityPeriod validityPeriod = new ValidityPeriod(date(2007, 1, 1), null);
        assertFalse(validityPeriod.isExpiredAt(date(1920, 1, 1)));
        assertFalse(validityPeriod.isExpiredAt(date(2020, 1, 1)));
    }

    @Test
    public void truncatedMillisDates() {
        long instant = 1502895557772L;

        final ValidityPeriod validityPeriod = new ValidityPeriod(new Date(instant), new Date(instant));

         assertEquals(validityPeriod.getNotValidBefore().getMillisOfSecond(), 0);
         assertEquals(validityPeriod.getNotValidAfter().getMillisOfSecond(), 0);
    }

    @Test
    public void truncatedMillisDateTimes() {
        long instant = 1502895557772L;

        final ValidityPeriod validityPeriod = new ValidityPeriod(new DateTime(instant), new DateTime(instant));

         assertEquals(validityPeriod.getNotValidBefore().getMillisOfSecond(), 0);
         assertEquals(validityPeriod.getNotValidAfter().getMillisOfSecond(), 0);
    }


    private ReadableInstant date(int year, int month, int day) {
        return new LocalDate(year, month, day).toDateTimeAtStartOfDay(DateTimeZone.UTC);
    }
}
