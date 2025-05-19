package net.ripe.rpki.commons.provisioning.x509.pkcs10;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class RpkiCaCertificateRequestParserTest {
    @Test
    void shouldThrowCaCertificateRequestParserException_on_null() {
        // When passed in null
        assertThatThrownBy(() -> new RpkiCaCertificateRequestParser(null))
            .isInstanceOf(RpkiCaCertificateRequestParserException.class);

        // Or when passed in object that has null properties (e.g. a mock)
        var mock = Mockito.mock(PKCS10CertificationRequest.class);
        assertThat(mock.getSubject()).isNull();

        assertThatThrownBy(() -> new RpkiCaCertificateRequestParser(mock))
            .isInstanceOf(RpkiCaCertificateRequestParserException.class);
    }
}
