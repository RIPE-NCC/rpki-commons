package net.ripe.certification.client.xml.converters;

import static org.junit.Assert.*;
import net.ripe.commons.certification.x509cert.X509PlainCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;

import org.junit.Before;
import org.junit.Test;

import com.thoughtworks.xstream.XStream;


public class X509ResourceCertificateConverterTest {

    private XStream xStream;
    private X509ResourceCertificateConverter subject;

    @Before
    public void setUp() {
        subject = new X509ResourceCertificateConverter();
        xStream = new XStream();
        xStream.registerConverter(subject);
    }

    @Test
    public void shouldSupportResourceCertificate() {
        assertTrue(subject.canConvert(X509ResourceCertificate.class));
    }

    @Test
    public void shouldSerializeResourceCertificate() {
        X509PlainCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        String xml = xStream.toXML(certificate);
        assertEquals(certificate, xStream.fromXML(xml));
        // Ensure the xml doesn't reference the java certificate interface
        assertFalse(xml.contains("java.security.cert.Certificate"));
    }

}
