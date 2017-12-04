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

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.DateTimeFormatterBuilder;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;

public class FixedDateRule implements MethodRule {

    private final long millis;


    public FixedDateRule(long millis) {
        this.millis = millis;
    }

    public FixedDateRule(DateTime dateTime) {
        this.millis = dateTime.getMillis();
    }

    /**
     * Set the date based on a readable string. Use format: yyyymmdd
     */
    public FixedDateRule(String yyyymmdd) {
        this.millis = convertDateTimeStringToMillis(yyyymmdd);
    }

    @Override
    public Statement apply(final Statement base, FrameworkMethod method, Object target) {
        return new Statement() {

            @Override
            public void evaluate() throws Throwable {
                DateTimeUtils.setCurrentMillisFixed(millis);
                try {
                    base.evaluate();
                } finally {
                    DateTimeUtils.setCurrentMillisSystem();
                }
            }
        };
    }

    public static void setDateTime(DateTime dateTime) {
        DateTimeUtils.setCurrentMillisFixed(dateTime.getMillis());
    }

    /**
     * Set the date based on a readable string. Use format: yyyymmdd
     */
    public static void setDateTime(String yyyymmdd) {
        DateTimeUtils.setCurrentMillisFixed(convertDateTimeStringToMillis(yyyymmdd));
    }

    private static long convertDateTimeStringToMillis(String yyyymmdd) {
        DateTimeFormatter dateTimeParser = new DateTimeFormatterBuilder().appendYear(4, 4).appendMonthOfYear(2).appendDayOfMonth(2).toFormatter().withZone(DateTimeZone.UTC);
        return dateTimeParser.parseDateTime(yyyymmdd).getMillis();
    }

    public static void restoreSystemTime() {
        DateTimeUtils.setCurrentMillisSystem();
    }
}
