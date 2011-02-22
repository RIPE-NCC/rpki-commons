package net.ripe.certification.client.xml.converters;

import static org.junit.Assert.*;

import java.util.regex.Pattern;

import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsTest;

import org.junit.Before;
import org.junit.Test;

import com.thoughtworks.xstream.XStream;

public class RoaCmsConverterTest {

    private XStream xStream;
    private RoaCmsConverter subject;

    private String expectedXmlRegEx =
    	"<net\\.ripe\\..*\\.RoaCms>\n" +
        "  <encoded>[^<]*</encoded>\n" +
        "</net\\.ripe\\..*\\.RoaCms>";

    @Before
    public void setUp() {
        subject = new RoaCmsConverter();
        xStream = new XStream();
        xStream.registerConverter(subject);
    }

    @Test
    public void shouldSupportResourceCertificate() {
        assertTrue(subject.canConvert(RoaCms.class));
    }

    @Test
    public void shouldOnlyUseEncodedWhenSerializingRoa() {
    	RoaCms roa = RoaCmsTest.getRoaCms();
    	String xml = xStream.toXML(roa);
    	assertTrue(Pattern.matches(expectedXmlRegEx, xml));
    }

    @Test
    public void shouldDoRoundTripSerializeAndDesirializeRoa() {
    	RoaCms roa = RoaCmsTest.getRoaCms();
    	String xml = xStream.toXML(roa);

    	RoaCms processedRoa = (RoaCms) xStream.fromXML(xml);

    	assertEquals(roa, processedRoa);
    }

}
