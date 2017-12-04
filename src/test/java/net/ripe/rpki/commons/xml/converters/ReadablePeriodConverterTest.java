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
