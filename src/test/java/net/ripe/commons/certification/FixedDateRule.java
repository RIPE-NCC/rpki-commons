package net.ripe.commons.certification;

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
