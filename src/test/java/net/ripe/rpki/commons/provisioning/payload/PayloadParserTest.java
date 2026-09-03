package net.ripe.rpki.commons.provisioning.payload;

import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.junit.Test;

import static org.junit.Assert.*;

public class PayloadParserTest {
    @Test
    public void shouldParseTypeFromMultilineMessageElement() {
        String message = """
                <?xml version="1.0" encoding="UTF-8"?>
                <message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
                         recipient="recipient"
                         sender="sender"
                         type="list"
                         version="1"/>
                """;
        ValidationResult result = ValidationResult.withLocation("a");
        AbstractProvisioningPayload wrapper = PayloadParser.parse(message, result);

        assertFalse(result.hasFailures());
        assertTrue(wrapper instanceof ResourceClassListQueryPayload);
    }

    @Test
    public void shouldNotParseUnknownType() {
        String message = """
                <?xml version="1.0" encoding="UTF-8"?>
                <message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
                         version="1"
                         sender="sender"
                         recipient="recipient"
                         type="unknown"/>
                """;

        ValidationResult result = ValidationResult.withLocation("a");
        AbstractProvisioningPayload wrapper = PayloadParser.parse(message, result);

        assertTrue(result.hasFailures());
        ValidationCheck validationCheck = result.getFailuresForCurrentLocation().iterator().next();
        assertEquals(ValidationString.VALID_PAYLOAD_TYPE, validationCheck.getKey());
        assertNull(wrapper);
    }


    @Test
    public void shouldNotParseWithoutType() {
        String message = """
                <?xml version="1.0" encoding="UTF-8"?>
                <message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
                         version="1"
                         sender="sender"
                         recipient="recipient"/>
                """;

        ValidationResult result = ValidationResult.withLocation("a");
        AbstractProvisioningPayload wrapper = PayloadParser.parse(message, result);

        assertTrue(result.hasFailures());
        ValidationCheck validationCheck = result.getFailuresForCurrentLocation().iterator().next();
        assertEquals(ValidationString.FOUND_PAYLOAD_TYPE, validationCheck.getKey());
        assertNull(wrapper);
    }
}
