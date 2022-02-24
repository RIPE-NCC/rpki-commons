package net.ripe.rpki.commons.provisioning.identity;


import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class PublisherRequestSerializerTest {

    static final String examplePublishRequest = "<publisher_request xmlns=\"http://www.hactrn.net/uris/rpki/rpki-setup/\" version=\"1\" publisher_handle=\"krill-testbed-prepdev\">\n" + "  " +
            "<publisher_bpki_ta>" +
            "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhDN0Q3" +
            "Q0NCREJDNEE5Njc1MTc0RTkwRjhFN0M4OURGQjEyQUZBQzAzMB4XDTIxMTIxNDEy" +
            "MjE0NVoXDTM2MTIxNDEyMjY0NVowMzExMC8GA1UEAxMoQzdEN0NDQkRCQzRBOTY3" +
            "NTE3NEU5MEY4RTdDODlERkIxMkFGQUMwMzCCASIwDQYJKoZIhvcNAQEBBQADggEP" +
            "ADCCAQoCggEBAOCG8f0dtfU0M5v6EMbtnob5NGYC0zKp2hlIlzgzyT2vG+Y6ami0" +
            "bwYOpp1g2AGg5ZoMZzkTnGjtbjYmmRd+OlbcqoW0ro6Gu1YVcMwEo9+QCBCguN3j" +
            "8Cgtr3Ed2NxqKC7hEtBiSGAjOQG1G8RrJGhw+C2XLw0GENNJ2vDzeEvrJ36obyy3" +
            "t6C7aZHooaNZd+efgn1VApSKzUv/1wyjvM3y8WgIT4xAlkGXQxJpZqeO8CViVy/y" +
            "46SwpuwJkduh+cC1eEu2QW7rk41aBlfvw6kiW8LwGJHsE2998Le1lSGyM81z+n/H" +
            "KBc4VvY+0yPzvwy0DbaGIFZJYiyp5/bopb0CAwEAAaNTMFEwDwYDVR0TAQH/BAUw" +
            "AwEB/zAdBgNVHQ4EFgQUx9fMvbxKlnUXTpD458id+xKvrAMwHwYDVR0jBBgwFoAU" +
            "x9fMvbxKlnUXTpD458id+xKvrAMwDQYJKoZIhvcNAQELBQADggEBAL1yIKvO7QRc" +
            "j1cQglh/qSlyrwcfG8LozOpMOwEDaEYdCfbO9C0qSQu3/fTMOTou0MyqPcA8JRXZ" +
            "9Pimf3j7s11+oHq74yzhgLFoGSChP8JkRVKzjt6HkiJt53ZUIyB1s83DcXif64XS" +
            "DGouUfWYiJD6KOXZFXtY/DLahDByr1lxEeQXHyAF6M44CzA/SeifTj9SsuQfvNT1" +
            "jYpFyEUTxQmhrjNMBiXGU9JmPwkAd6RvjrLDN0YCKjPEsGHBo2TpFhupR5wAp0Om" +
            "fVN1nCV2F7eAeeqsfKqspC1XV5fRwhSEl/fx+ZxWsnDXUpFUij0lTCsKXj9b2F05" +
            "L/q2X/7Tjpk=</publisher_bpki_ta>\n" +
            "</publisher_request>";

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