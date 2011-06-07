package net.ripe.commons.provisioning.serialization;

import static org.junit.Assert.*;

import java.net.URI;
import java.util.Arrays;

import org.junit.Test;


public class CertificateUrlListConverterTest {

    private static final URI URI_WITH_COMMA = URI.create("http://localhost/unescaped,comma"); 
    private static final URI URI_WITH_ESCAPED_COMMA = URI.create("http://localhost/escaped%2Ccomma");
    
    private CertificateUrlListConverter subject = new CertificateUrlListConverter();
    
    @Test
    public void shouldEscapeCommasInUris() {
        assertEquals("http://localhost/unescaped%2Ccomma", subject.toString(Arrays.asList(URI_WITH_COMMA)));
    }
    
    @Test
    public void shouldSeparateUrisWithCommas() {
        assertEquals("http://localhost/unescaped%2Ccomma,http://localhost/escaped%2Ccomma", subject.toString(Arrays.asList(URI_WITH_COMMA, URI_WITH_ESCAPED_COMMA)));
    }
    
    @Test
    public void shouldNotUnescapeCommas() {
        assertEquals(Arrays.asList(URI.create("http://localhost/unescaped%2Ccomma"), URI_WITH_ESCAPED_COMMA), subject.fromString("http://localhost/unescaped%2Ccomma,http://localhost/escaped%2Ccomma"));
    }
    
}
