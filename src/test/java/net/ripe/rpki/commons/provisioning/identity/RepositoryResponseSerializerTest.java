package net.ripe.rpki.commons.provisioning.identity;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class RepositoryResponseSerializerTest  {

    static final String exampleRepositoryResponse =
            "<repository_response xmlns=\"http://www.hactrn.net/uris/rpki/rpki-setup/\" " +
            "version=\"1\" publisher_handle=\"krill-testbed-prepdev1645011427044\" " +
            "service_uri=\"https://testbed.krill.cloud/rfc8181/krill-testbed-prepdev1645011427044/\" " +
            "sia_base=\"rsync://testbed.krill.cloud/repo/krill-testbed-prepdev1645011427044/\" " +
            "rrdp_notification_uri=\"https://testbed.krill.cloud/rrdp/notification.xml\">\n" + "  " +
            "<repository_bpki_ta>" +
                    "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEygyNEI3" +
                    "QUMyREE5OTAyMzM2NTdFQ0E5MTZGOTYyOEREQTEyNDY4RDU5MB4XDTIxMTEyNTEw" +
                    "MjUxNVoXDTM2MTEyNTEwMzAxNVowMzExMC8GA1UEAxMoMjRCN0FDMkRBOTkwMjMz" +
                    "NjU3RUNBOTE2Rjk2MjhEREExMjQ2OEQ1OTCCASIwDQYJKoZIhvcNAQEBBQADggEP" +
                    "ADCCAQoCggEBAOk2+4MzVtTGLNYZT/TE/2ulAyEKE3rSxNKB0YyqXjYGr5i0d+1B" +
                    "y2P+DgbUTD9nG41XqtlDl58XGE/Q2Kw9Aj1iIMcqhtQ71Tb1ZtEtc+AmK/2ffCtD" +
                    "mWgGHXbs7peytJUYfxGRcU9fmnL8EzcazgKA/Vj4wtkJ6Flc+W4aIY0qzzvkTlzZ" +
                    "CE5L8mOmSaXGk+jkNNDm8IxewzwVanqVigdWSkyRCzYw26fuf+IlwSmSpvM2EQHY" +
                    "bujb+5RIVwWPeGdI3djjaDWBDyb7Ngd32dDt5F+xuRbYNJXjqCttTk8dN0WCTJGP" +
                    "7HiCewttfOYnucbB8xVzFLl2KSMBPIuRCEkCAwEAAaNTMFEwDwYDVR0TAQH/BAUw" +
                    "AwEB/zAdBgNVHQ4EFgQUJLesLamQIzZX7KkW+WKN2hJGjVkwHwYDVR0jBBgwFoAU" +
                    "JLesLamQIzZX7KkW+WKN2hJGjVkwDQYJKoZIhvcNAQELBQADggEBAN7WZ0qc51KS" +
                    "dhnRX1kDMNbRYdu5/q9dK+Y6NCdiXSTsDSKkKPCXOkKqmim3f0wk1wS9AjT8IhWO" +
                    "raQyPQkasJfa2hGu9V550kA8G/BuwfBs5Q1wNLudgPjjSdb8dT3z47S8A59eVlIF" +
                    "ZeQhD+gFCloHejkdVDm3I/AFBo8rPvmwqnBUos+lrY7R0PaLkQ3mhmZI+2LTqaGH" +
                    "8fmcQy2NTvTEtHY6fMVxCQuIflH/lgPEmd26OmSMl0tAdHx3ADNUOiiA1h+PdEFa" +
                    "Ad5r2+jN48/DDAMN9ncvzc/7+akMYNP4ygUUrvNBF1gWmorG7DRei4/0zqkQLBm9" +
                    "Dim/s1lKS4o=</repository_bpki_ta>\n" +
            "</repository_response>";

    @Test
    public void testDeserializeXML() {
        RepositoryResponseSerializer serializer = new RepositoryResponseSerializer();
        RepositoryResponse repositoryResponse = serializer.deserialize(exampleRepositoryResponse);

        assertEquals("krill-testbed-prepdev1645011427044", repositoryResponse.getPublisherHandle());
        assertEquals("https://testbed.krill.cloud/rfc8181/krill-testbed-prepdev1645011427044/", repositoryResponse.getServiceUri().toString());
        assertEquals("rsync://testbed.krill.cloud/repo/krill-testbed-prepdev1645011427044/", repositoryResponse.getSiaBase().toString());
        assertEquals("https://testbed.krill.cloud/rrdp/notification.xml", repositoryResponse.getRrdpNotificationUri().get().toString());
        assertEquals("CN=24B7AC2DA990233657ECA916F9628DDA12468D59", repositoryResponse.getRepositoryBpkiTa().getSubject().getName());
    }

    @Test
    public void shouldDoRoundTripDezerializeSerialize() {
        RepositoryResponseSerializer serializer = new RepositoryResponseSerializer();
        RepositoryResponse repositoryResponse = serializer.deserialize(exampleRepositoryResponse);

        String xml = serializer.serialize(repositoryResponse);
        RepositoryResponse anotherRound = serializer.deserialize(xml);

        assertEquals(anotherRound, repositoryResponse);
    }

    @Test
    public void shouldFailToParseCorruptedXML() {
        RepositoryResponseSerializer serializer = new RepositoryResponseSerializer();
        Exception exception = assertThrows(IdentitySerializer.IdentitySerializerException.class, () -> {
            serializer.deserialize(exampleRepositoryResponse.replaceAll("repository_response", "publisher_request") );
        });

        assertEquals("repository_response element not found", exception.getMessage());
    }

}
