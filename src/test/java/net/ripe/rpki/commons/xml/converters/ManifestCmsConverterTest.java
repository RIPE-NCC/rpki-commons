package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.XStream;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.regex.Pattern;


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
        xStream.allowTypes(new Class[]{ManifestCms.class});
    }

    @Test
    public void shouldSupportResourceCertificate() {
        Assert.assertTrue(subject.canConvert(ManifestCms.class));
    }

    @Test
    public void shouldOnlyUseEncodedWhenSerializingManifest() {
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();
        String xml = xStream.toXML(manifestCms);
        Assert.assertTrue(Pattern.matches(expectedXmlRegEx, xml));
    }

    @Test
    public void shouldDoRoundTripSerializeAndDesirializeManifest() {
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

        String xml = xStream.toXML(manifestCms);
        ManifestCms processedManifest = (ManifestCms) xStream.fromXML(xml);

        Assert.assertEquals(manifestCms, processedManifest);
    }
}
