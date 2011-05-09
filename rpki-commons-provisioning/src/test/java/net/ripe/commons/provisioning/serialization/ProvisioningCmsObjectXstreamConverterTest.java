package net.ripe.commons.provisioning.serialization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.regex.Pattern;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.certification.client.xml.XStreamXmlSerializerBuilder;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;

import org.junit.Before;
import org.junit.Test;


public class ProvisioningCmsObjectXstreamConverterTest {

    private XStreamXmlSerializer<ProvisioningCmsObject> serializer;

    @Before
    public void given() {
        XStreamXmlSerializerBuilder<ProvisioningCmsObject> xStreamXmlSerializerBuilder = new XStreamXmlSerializerBuilder<ProvisioningCmsObject>(ProvisioningCmsObject.class);
        xStreamXmlSerializerBuilder.withConverter(new ProvisioningCmsObjectXstreamConverter());
        xStreamXmlSerializerBuilder.withAliasType("ProvisioningCmsObject", ProvisioningCmsObject.class);
        serializer = xStreamXmlSerializerBuilder.build();
    }
    
    @Test
    public void shouldRoundTrip() {
        ProvisioningCmsObject cmsObject = ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject();
        String xml = serializer.serialize(cmsObject);
        ProvisioningCmsObject deserializedCmsObject = serializer.deserialize(xml);
        assertEquals(cmsObject, deserializedCmsObject);
    }
    
    @Test
    public void shouldUseSimpleXml() {
        ProvisioningCmsObject cmsObject = ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject();
        String xml = serializer.serialize(cmsObject);
        
        String expectedRegex = "<ProvisioningCmsObject>\n" +
                               "  <encoded>[^<]*</encoded>\n" +
                               "</ProvisioningCmsObject>";

        assertTrue(Pattern.matches(expectedRegex, xml));
    }
    
}
