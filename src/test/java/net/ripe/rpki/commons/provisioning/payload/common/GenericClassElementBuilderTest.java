package net.ripe.rpki.commons.provisioning.payload.common;

import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

public class GenericClassElementBuilderTest {

    // https://datatracker.ietf.org/doc/html/rfc6492#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        GenericClassElementBuilder builder = new GenericClassElementBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(Arrays.asList(URI.create("http://some/other")));
        builder.buildResourceClassListResponseClassElement();
    }
}
