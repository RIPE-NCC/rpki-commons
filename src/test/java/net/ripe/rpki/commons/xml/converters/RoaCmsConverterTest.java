package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.XStream;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsObjectMother;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.regex.Pattern;

public class RoaCmsConverterTest {

    private XStream xStream;
    private RoaCmsConverter subject;

    private final String expectedXmlRegEx = """
            <net\\.ripe\\..*\\.RoaCms>
              <encoded>[^<]*</encoded>
            </net\\.ripe\\..*\\.RoaCms>""";

    @Before
    public void setUp() {
        subject = new RoaCmsConverter();
        xStream = new XStream();
        xStream.registerConverter(subject);
        xStream.allowTypes(new Class[]{RoaCms.class});
    }

    @Test
    public void shouldSupportResourceCertificate() {
        Assert.assertTrue(subject.canConvert(RoaCms.class));
    }

    @Test
    public void shouldOnlyUseEncodedWhenSerializingRoa() {
        RoaCms roa = RoaCmsObjectMother.getRoaCms(ZonedDateTime.now(ZoneOffset.UTC));
        String xml = xStream.toXML(roa);
        Assert.assertTrue(Pattern.matches(expectedXmlRegEx, xml));
    }

    @Test
    public void shouldDoRoundTripSerializeAndDesirializeRoa() {
        RoaCms roa = RoaCmsObjectMother.getRoaCms(ZonedDateTime.now(ZoneOffset.UTC));
        String xml = xStream.toXML(roa);

        RoaCms processedRoa = (RoaCms) xStream.fromXML(xml);

        Assert.assertEquals(roa, processedRoa);
    }

}
