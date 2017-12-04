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

import com.thoughtworks.xstream.converters.SingleValueConverter;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;


public class DateTimeConverter implements SingleValueConverter {

    private static final DateTimeFormatter FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE = ISODateTimeFormat.dateTime().withZone(DateTimeZone.UTC);

    private static final DateTimeFormatter FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE = ISODateTimeFormat.dateTimeNoMillis().withZone(DateTimeZone.UTC);

    private boolean useMillis = false;

    public DateTimeConverter() {
    }

    public DateTimeConverter(boolean useMillis) {
        this.useMillis = useMillis;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean canConvert(Class type) {
        return DateTime.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        try {
            return FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE.parseDateTime(s);
        } catch (IllegalArgumentException e) {
            return FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE.parseDateTime(s);
        }
    }

    @Override
    public String toString(Object datetime) {
        // TODO: Test this! Was failing for me when running unit tests from different time zone
        DateTime dateTimeWithZone = ((DateTime) datetime).withZone(DateTimeZone.UTC);
        if (useMillis) {
            return FORMATTER_DATE_TIME_WITH_MILLIS_AND_ZONE.print(dateTimeWithZone);
        } else {
            return FORMATTER_DATE_TIME_NO_MILLIS_AND_ZONE.print(dateTimeWithZone);
        }
    }
}
