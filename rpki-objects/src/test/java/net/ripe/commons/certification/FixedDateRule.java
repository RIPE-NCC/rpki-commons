package net.ripe.commons.certification;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
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
}
