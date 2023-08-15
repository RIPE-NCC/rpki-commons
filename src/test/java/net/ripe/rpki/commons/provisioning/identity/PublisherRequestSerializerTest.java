package net.ripe.rpki.commons.provisioning.identity;


import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class PublisherRequestSerializerTest {

    static final String examplePublishRequest = """
        <publisher_request xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" publisher_handle="krill-testbed-prepdev">
          <publisher_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhDN0Q3Q0NCREJDNEE5Njc1MTc0RTkwRjhFN0M4OURGQjEyQUZBQzAzMB4XDTIxMTIxNDEyMjE0NVoXDTM2MTIxNDEyMjY0NVowMzExMC8GA1UEAxMoQzdEN0NDQkRCQzRBOTY3NTE3NEU5MEY4RTdDODlERkIxMkFGQUMwMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCG8f0dtfU0M5v6EMbtnob5NGYC0zKp2hlIlzgzyT2vG+Y6ami0bwYOpp1g2AGg5ZoMZzkTnGjtbjYmmRd+OlbcqoW0ro6Gu1YVcMwEo9+QCBCguN3j8Cgtr3Ed2NxqKC7hEtBiSGAjOQG1G8RrJGhw+C2XLw0GENNJ2vDzeEvrJ36obyy3t6C7aZHooaNZd+efgn1VApSKzUv/1wyjvM3y8WgIT4xAlkGXQxJpZqeO8CViVy/y46SwpuwJkduh+cC1eEu2QW7rk41aBlfvw6kiW8LwGJHsE2998Le1lSGyM81z+n/HKBc4VvY+0yPzvwy0DbaGIFZJYiyp5/bopb0CAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUx9fMvbxKlnUXTpD458id+xKvrAMwHwYDVR0jBBgwFoAUx9fMvbxKlnUXTpD458id+xKvrAMwDQYJKoZIhvcNAQELBQADggEBAL1yIKvO7QRcj1cQglh/qSlyrwcfG8LozOpMOwEDaEYdCfbO9C0qSQu3/fTMOTou0MyqPcA8JRXZ9Pimf3j7s11+oHq74yzhgLFoGSChP8JkRVKzjt6HkiJt53ZUIyB1s83DcXif64XSDGouUfWYiJD6KOXZFXtY/DLahDByr1lxEeQXHyAF6M44CzA/SeifTj9SsuQfvNT1jYpFyEUTxQmhrjNMBiXGU9JmPwkAd6RvjrLDN0YCKjPEsGHBo2TpFhupR5wAp0OmfVN1nCV2F7eAeeqsfKqspC1XV5fRwhSEl/fx+ZxWsnDXUpFUij0lTCsKXj9b2F05L/q2X/7Tjpk=</publisher_bpki_ta>
        </publisher_request>""";

    @Test
    public void testDeserializeXML() {
        PublisherRequestSerializer serializer = new PublisherRequestSerializer();
        PublisherRequest publisherRequest = serializer.deserialize(examplePublishRequest);

        assertEquals("krill-testbed-prepdev", publisherRequest.getPublisherHandle());
        assertEquals("CN=C7D7CCBDBC4A9675174E90F8E7C89DFB12AFAC03", publisherRequest.getPublisherBpkiTa().getSubject().getName());
    }

    @Test
    public void shouldDoRoundTripDezerializeSerialize() {
        PublisherRequestSerializer serializer = new PublisherRequestSerializer();
        PublisherRequest publisherRequest = serializer.deserialize(examplePublishRequest);

        String xml = serializer.serialize(publisherRequest);
        PublisherRequest anotherRound = serializer.deserialize(xml);

        assertEquals(anotherRound, publisherRequest);
    }

    @Test
    public void shouldFailToParseCorruptedXML() {
        PublisherRequestSerializer serializer = new PublisherRequestSerializer();
        Exception exception = assertThrows(IdentitySerializer.IdentitySerializerException.class, () -> {
            serializer.deserialize(examplePublishRequest.replaceAll("publisher_request", "publisher_response") );
        });

        assertEquals("publisher_request element not found", exception.getMessage());
    }
}