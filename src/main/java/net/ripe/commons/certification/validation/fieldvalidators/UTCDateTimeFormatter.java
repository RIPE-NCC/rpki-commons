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
package net.ripe.commons.certification.validation.fieldvalidators;

import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.DateTimeFormatterBuilder;

/**
 *  Controls the printing and parsing of a datetime to and from a string.
 *  This formatter is using the UTC timezone for printing and parsing objects.
 *  This class is a singleton and the formatter instance it returns is
 *  thread-safe and immutable.
 */
public final class UTCDateTimeFormatter {

    private static final int MIN_DIGITS_FOR_YEARS = 4;
    private static final int MAX_DIGITS_FOR_YEARS = 4;
    private static final int MIN_DIGITS_FOR_MONTH = 2;
    private static final int MIN_DIGITS_FOR_DAY = 2;
    private static final int MIN_DIGITS_FOR_HOUR = 2;
    private static final int MIN_DIGITS_FOR_MINUTE = 2;

    private static final DateTimeFormatter FORMATTER = new DateTimeFormatterBuilder()
    .appendYear(MIN_DIGITS_FOR_YEARS, MAX_DIGITS_FOR_YEARS).appendLiteral('-').appendMonthOfYear(MIN_DIGITS_FOR_MONTH)
    .appendLiteral('-').appendDayOfMonth(MIN_DIGITS_FOR_DAY)
    .appendLiteral(' ').appendHourOfDay(MIN_DIGITS_FOR_HOUR)
    .appendLiteral(':').appendMinuteOfHour(MIN_DIGITS_FOR_MINUTE)
    .toFormatter().withZone(DateTimeZone.UTC);

    private UTCDateTimeFormatter() {
    }

    public static DateTimeFormatter getInstance() {
        return FORMATTER;
    }
}
