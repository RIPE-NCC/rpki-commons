package net.ripe.rpki.commons.util;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.time.Instant;

public class UTC {
    public static DateTime dateTime() {
        return new DateTime(DateTimeZone.UTC);
    }

    public static DateTime dateTime(Object o) {
        return new DateTime(o, DateTimeZone.UTC);
    }

    public static Instant instant() {
        return Instant.now();
    }
}
