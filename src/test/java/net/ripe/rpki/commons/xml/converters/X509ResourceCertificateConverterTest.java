package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.XStream;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class X509ResourceCertificateConverterTest {

    private XStream xStream;
    private X509ResourceCertificateConverter subject;

    @Before
    public void setUp() {
        subject = new X509ResourceCertificateConverter();
        xStream = new XStream();
        xStream.registerConverter(subject);
        xStream.allowTypes(new Class<?>[]{X509ResourceCertificate.class});
    }

    @Test
    public void shouldSupportResourceCertificate() {
        Assert.assertTrue(subject.canConvert(X509ResourceCertificate.class));
    }

    @Test
    public void shouldSerializeResourceCertificate() {
        X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        String xml = xStream.toXML(certificate);
        Assert.assertEquals(certificate, xStream.fromXML(xml));
        // Ensure the xml doesn't reference the java certificate interface
        Assert.assertFalse(xml.contains("java.security.cert.Certificate"));
    }

}
