package net.ripe.rpki.commons.provisioning.cms;

import com.google.common.io.Resources;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;

import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ProvisioningCmsObjectParserTest {

    private ProvisioningCmsObjectParser subject;


    @BeforeEach
    public void setUp() {
        subject = new ProvisioningCmsObjectParser();
    }

    @Test
    public void shouldParseValidObject() {
        ProvisioningCmsObject cmsObject = ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject();
        subject.parseCms("test-location", cmsObject.getEncoded());

        ValidationResult validationResult = subject.getValidationResult();
        assertThat(validationResult.hasFailures()).isFalse();
        assertThat(subject.getProvisioningCmsObject()).isEqualTo(cmsObject);
    }

    @CsvSource({
            "isc-interop-updown/pdu.170.der",
            "isc-interop-updown/pdu.171.der",
            "isc-interop-updown/pdu.172.der",
            "isc-interop-updown/pdu.173.der",
            "isc-interop-updown/pdu.180.der",
            "isc-interop-updown/pdu.183.der",
            "isc-interop-updown/pdu.184.der",
            "isc-interop-updown/pdu.189.der",
            "isc-interop-updown/pdu.196.der",
            "isc-interop-updown/pdu.199.der",
            "isc-interop-updown/pdu.200.der",
            "isc-interop-updown/pdu.205.der",
    })
    @ParameterizedTest(name = "{displayName} - {0}")
    public void shouldParseInteropObjects(String interopFileName) throws IOException {
        byte[] object = Resources.toByteArray(Resources.getResource(interopFileName));

        subject.parseCms(interopFileName, object);
        assertThat(subject.getValidationResult().hasFailures()).isFalse();
        assertThat(subject.getProvisioningCmsObject().getSigningTime()).isBetween(DateTime.parse("2011-07-01T00:00:00Z"), DateTime.parse("2011-08-01T00:00:00Z"));
    }

    @Test
    public void shouldFailOnInvalidObject() {
        subject.parseCms("test-location", new byte[]{0});

        ValidationResult validationResult = subject.getValidationResult();
        assertThat(validationResult.hasFailures()).isTrue();
        assertThat(validationResult.getFailuresForCurrentLocation()).hasSize(1);
        assertThat(validationResult.getFailuresForCurrentLocation().iterator().next().getKey()).isEqualTo(CMS_DATA_PARSING);

        assertThatThrownBy(() -> subject.getProvisioningCmsObject())
                .isInstanceOf(ProvisioningCmsObjectParserException.class);
    }
}
