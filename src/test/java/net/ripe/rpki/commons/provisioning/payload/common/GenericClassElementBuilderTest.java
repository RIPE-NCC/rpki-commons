package net.ripe.rpki.commons.provisioning.payload.common;

import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

public class GenericClassElementBuilderTest {

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        GenericClassElementBuilder builder = new GenericClassElementBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(Arrays.asList(URI.create("http://some/other")));
        builder.buildResourceClassListResponseClassElement();
    }
}
