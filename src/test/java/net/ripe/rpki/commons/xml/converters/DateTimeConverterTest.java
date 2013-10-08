/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
