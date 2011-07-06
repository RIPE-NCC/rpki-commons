package net.ripe.certification.client.xml.converters;

import static org.junit.Assert.*;

import java.util.regex.Pattern;

import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;

import org.junit.Before;
import org.junit.Test;

import com.thoughtworks.xstream.XStream;


public class ManifestCmsConverterTest {

    private XStream xStream;
    private ManifestCmsConverter subject;

    private String expectedXmlRegEx =
    	"<net\\.ripe\\..*\\.ManifestCms>\n" +
        "  <encoded>[^<]*</encoded>\n" +
        "</net\\.ripe\\..*\\.ManifestCms>";

    @Before
    public void setUp() {
        subject = new ManifestCmsConverter();
        xStream = new XStream();
        xStream.registerConverter(subject);
    }

    @Test
    public void shouldSupportResourceCertificate() {
        assertTrue(subject.canConvert(ManifestCms.class));
    }

    @Test
    public void shouldOnlyUseEncodedWhenSerializingManifest() {
    	ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();
    	String xml = xStream.toXML(manifestCms);
    	assertTrue(Pattern.matches(expectedXmlRegEx, xml));
    }

    @Test
    public void shouldDoRoundTripSerializeAndDesirializeManifest() {
    	ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

    	String xml = xStream.toXML(manifestCms);
    	ManifestCms processedManifest = (ManifestCms) xStream.fromXML(xml);

    	assertEquals(manifestCms, processedManifest);
    }
}
