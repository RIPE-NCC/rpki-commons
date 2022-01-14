package net.ripe.rpki.commons.validation;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class ValidationStatusTest {
    @Test
    public void should_format_message_key() throws Exception {
        assertEquals("error", ValidationStatus.ERROR.getMessageKey());
        assertEquals("error", ValidationStatus.FETCH_ERROR.getMessageKey());
        assertEquals("passed", ValidationStatus.PASSED.getMessageKey());
        assertEquals("warning", ValidationStatus.WARNING.getMessageKey());
    }

}
