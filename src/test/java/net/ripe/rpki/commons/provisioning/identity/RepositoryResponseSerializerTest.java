package net.ripe.rpki.commons.provisioning.identity;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class RepositoryResponseSerializerTest  {

    static final String exampleRepositoryResponse = """
            <repository_response xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" publisher_handle="krill-testbed-prepdev1645011427044" service_uri="https://testbed.krill.cloud/rfc8181/krill-testbed-prepdev1645011427044/" sia_base="rsync://testbed.krill.cloud/repo/krill-testbed-prepdev1645011427044/" rrdp_notification_uri="https://testbed.krill.cloud/rrdp/notification.xml">
              <repository_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEygyNEI3QUMyREE5OTAyMzM2NTdFQ0E5MTZGOTYyOEREQTEyNDY4RDU5MB4XDTIxMTEyNTEwMjUxNVoXDTM2MTEyNTEwMzAxNVowMzExMC8GA1UEAxMoMjRCN0FDMkRBOTkwMjMzNjU3RUNBOTE2Rjk2MjhEREExMjQ2OEQ1OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOk2+4MzVtTGLNYZT/TE/2ulAyEKE3rSxNKB0YyqXjYGr5i0d+1By2P+DgbUTD9nG41XqtlDl58XGE/Q2Kw9Aj1iIMcqhtQ71Tb1ZtEtc+AmK/2ffCtDmWgGHXbs7peytJUYfxGRcU9fmnL8EzcazgKA/Vj4wtkJ6Flc+W4aIY0qzzvkTlzZCE5L8mOmSaXGk+jkNNDm8IxewzwVanqVigdWSkyRCzYw26fuf+IlwSmSpvM2EQHYbujb+5RIVwWPeGdI3djjaDWBDyb7Ngd32dDt5F+xuRbYNJXjqCttTk8dN0WCTJGP7HiCewttfOYnucbB8xVzFLl2KSMBPIuRCEkCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJLesLamQIzZX7KkW+WKN2hJGjVkwHwYDVR0jBBgwFoAUJLesLamQIzZX7KkW+WKN2hJGjVkwDQYJKoZIhvcNAQELBQADggEBAN7WZ0qc51KSdhnRX1kDMNbRYdu5/q9dK+Y6NCdiXSTsDSKkKPCXOkKqmim3f0wk1wS9AjT8IhWOraQyPQkasJfa2hGu9V550kA8G/BuwfBs5Q1wNLudgPjjSdb8dT3z47S8A59eVlIFZeQhD+gFCloHejkdVDm3I/AFBo8rPvmwqnBUos+lrY7R0PaLkQ3mhmZI+2LTqaGH8fmcQy2NTvTEtHY6fMVxCQuIflH/lgPEmd26OmSMl0tAdHx3ADNUOiiA1h+PdEFaAd5r2+jN48/DDAMN9ncvzc/7+akMYNP4ygUUrvNBF1gWmorG7DRei4/0zqkQLBm9Dim/s1lKS4o=</repository_bpki_ta>
            </repository_response>""";

    @Test
    public void testDeserializeXML() {
        RepositoryResponseSerializer serializer = new RepositoryResponseSerializer();
        RepositoryResponse repositoryResponse = serializer.deserialize(exampleRepositoryResponse);

        assertEquals("krill-testbed-prepdev1645011427044", repositoryResponse.publisherHandle());
        assertEquals("https://testbed.krill.cloud/rfc8181/krill-testbed-prepdev1645011427044/", repositoryResponse.serviceUri().toString());
        assertEquals("rsync://testbed.krill.cloud/repo/krill-testbed-prepdev1645011427044/", repositoryResponse.siaBase().toString());
        assertEquals("https://testbed.krill.cloud/rrdp/notification.xml", repositoryResponse.rrdpNotificationUri().get().toString());
        assertEquals("CN=24B7AC2DA990233657ECA916F9628DDA12468D59", repositoryResponse.repositoryBpkiTa().getSubject().getName());
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
