package net.ripe.rpki.commons.provisioning.serialization;

import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import org.junit.Before;
import org.junit.Test;

import java.util.regex.Pattern;

import static org.junit.Assert.*;


public class ProvisioningCmsObjectXstreamConverterTest {

    private static final boolean NOT_STRICT = false;
    private XStreamXmlSerializer<ProvisioningCmsObject> serializer;

    @Before
    public void given() {
        XStreamXmlSerializerBuilder<ProvisioningCmsObject> xStreamXmlSerializerBuilder = XStreamXmlSerializerBuilder.newForgivingXmlSerializerBuilder(ProvisioningCmsObject.class);
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

        String expectedRegex = """
            <ProvisioningCmsObject>
              <encoded>[^<]*</encoded>
            </ProvisioningCmsObject>""";

        assertTrue(Pattern.matches(expectedRegex, xml));
    }

}
