package net.ripe.commons.provisioning.message;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.provisioning.message.issue.response.CertificateIssuanceResponsePayloadWrapper;

import org.junit.Test;

public class PayloadParserTest {
    @Test
    public void shouldParseIssueResponse() {
        String message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"issue_response\">\n" +
                "  <class class_name=\"a classname\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"1234,456\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::\" resource_set_notafter=\"2011-01-01T22:58:23.012Z\">\n" +
                "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:0DB8::/48\">MIICmDCCAkKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwl6ei5pc3N1ZXIwHhcN\n" +
                "MTEwMjI4MjMwMDAwWhcNMTYwMjI5MjMwMDAwWjAVMRMwEQYDVQQDEwp6ei5zdWJqZWN0MIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlrHH0zGtS3xGsUQr863pYAsqH5jSnJrNxFOZuI9p\n" +
                "QOCTmCTJiQy1T3Xg6Vqo1qzi+l2IGBROdjO65XjTe45ZPo4HgdL6ZI+yiXmq3kvX2BBaOxqNnZXn\n" +
                "JcIuy82vSSTolN8pHjR1dwjU0BO2vBNQ4/yihiWNl/0IMDGy3c9rcaNHQN7rv4EMmzdg2B9cWt0V\n" +
                "DrI+cCb2ZoM0Di+tCuKYDZh+4jDpRP42FlmNNctLPCDN4n3iyrzLuJxfRkeTMYRBMQEoJa/j0p4l\n" +
                "Mm1jXgEe7VW/gH4cwUbncnsXIfJ3oMTJcF8sec14FFaqdmy+hMxZur1V0I/zZdqqMxWC2GhvtwID\n" +
                "AQABo4G1MIGyMB0GA1UdDgQWBBSOnD5i2r2WmFK8837eeC+s1QXOgjAfBgNVHSMEGDAWgBQt0lf+\n" +
                "OyuHTAqWlgDrkpP5MDRAeDAYBgNVHSABAf8EDjAMMAoGCCsGAQUFBw4CMDMGCCsGAQUFBwEHAQH/\n" +
                "BCQwIjAUBAIAATAOAwIACgMDBKwQAwMAwKgwCgQCAAIwBAMCAfwwIQYIKwYBBQUHAQgBAf8EEjAQ\n" +
                "oA4wDDAKAgMA/AACAwD//jANBgkqhkiG9w0BAQsFAANBAFNGWOXNqQjzyQvSYTdxoCmuuK5KgPv4\n" +
                "vDLt9ibnaCWb3lJdvIeWVclaC+4MyaQbscw0CPMTdgGbTrq/NTrKCxM=</certificate>\n" +
                "    <issuer>MIICmDCCAkKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwl6ei5pc3N1ZXIwHhcN\n" +
                "MTEwMjI4MjMwMDAwWhcNMTYwMjI5MjMwMDAwWjAVMRMwEQYDVQQDEwp6ei5zdWJqZWN0MIIBIjAN\n" +
                "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlrHH0zGtS3xGsUQr863pYAsqH5jSnJrNxFOZuI9p\n" +
                "QOCTmCTJiQy1T3Xg6Vqo1qzi+l2IGBROdjO65XjTe45ZPo4HgdL6ZI+yiXmq3kvX2BBaOxqNnZXn\n" +
                "JcIuy82vSSTolN8pHjR1dwjU0BO2vBNQ4/yihiWNl/0IMDGy3c9rcaNHQN7rv4EMmzdg2B9cWt0V\n" +
                "DrI+cCb2ZoM0Di+tCuKYDZh+4jDpRP42FlmNNctLPCDN4n3iyrzLuJxfRkeTMYRBMQEoJa/j0p4l\n" +
                "Mm1jXgEe7VW/gH4cwUbncnsXIfJ3oMTJcF8sec14FFaqdmy+hMxZur1V0I/zZdqqMxWC2GhvtwID\n" +
                "AQABo4G1MIGyMB0GA1UdDgQWBBSOnD5i2r2WmFK8837eeC+s1QXOgjAfBgNVHSMEGDAWgBQt0lf+\n" +
                "OyuHTAqWlgDrkpP5MDRAeDAYBgNVHSABAf8EDjAMMAoGCCsGAQUFBw4CMDMGCCsGAQUFBwEHAQH/\n" +
                "BCQwIjAUBAIAATAOAwIACgMDBKwQAwMAwKgwCgQCAAIwBAMCAfwwIQYIKwYBBQUHAQgBAf8EEjAQ\n" +
                "oA4wDDAKAgMA/AACAwD//jANBgkqhkiG9w0BAQsFAANBAFNGWOXNqQjzyQvSYTdxoCmuuK5KgPv4\n" +
                "vDLt9ibnaCWb3lJdvIeWVclaC+4MyaQbscw0CPMTdgGbTrq/NTrKCxM=</issuer>\n" +
                "  </class>\n" +
                "</message>";

        ValidationResult result = new ValidationResult();
        result.push("a");

        ProvisioningPayloadWrapper wrapper = PayloadParser.parse(message.getBytes(), result);
        assertFalse(result.hasFailures());
        assertEquals(CertificateIssuanceResponsePayloadWrapper.class, wrapper.getClass());


    }

    @Test
    public void shouldNotParseUnknownType() {
        String message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"unknown\" />";

        ValidationResult result = new ValidationResult();
        result.push("a");
        ProvisioningPayloadWrapper wrapper = PayloadParser.parse(message.getBytes(), result);

        assertTrue(result.hasFailures());
        ValidationCheck validationCheck = result.getFailuresForCurrentLocation().iterator().next();
        assertEquals(ValidationString.VALID_PAYLOAD_TYPE, validationCheck.getKey());
        assertNull(wrapper);
    }


    @Test
    public void shouldNotParseWithoutType() {
        String message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\"  />";

        ValidationResult result = new ValidationResult();
        result.push("a");
        ProvisioningPayloadWrapper wrapper = PayloadParser.parse(message.getBytes(), result);

        assertTrue(result.hasFailures());
        ValidationCheck validationCheck = result.getFailuresForCurrentLocation().iterator().next();
        assertEquals(ValidationString.FOUND_PAYLOAD_TYPE, validationCheck.getKey());
        assertNull(wrapper);
    }

}
