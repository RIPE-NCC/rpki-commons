package net.ripe.commons.provisioning.serialization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.regex.Pattern;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.certification.client.xml.XStreamXmlSerializerBuilder;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;

import org.junit.Before;
import org.junit.Test;


public class ProvisioningIdentityCertificateXstreamConverterTest {

    private XStreamXmlSerializer<ProvisioningIdentityCertificate> serializer;

    @Before
    public void given() {
        XStreamXmlSerializerBuilder<ProvisioningIdentityCertificate> xStreamXmlSerializerBuilder = new XStreamXmlSerializerBuilder<ProvisioningIdentityCertificate>(ProvisioningIdentityCertificate.class);
        xStreamXmlSerializerBuilder.withConverter(new ProvisioningIdentityCertificateXstreamConverter());
        xStreamXmlSerializerBuilder.withAliasType("ProvisioningIdentityCertificate", ProvisioningIdentityCertificate.class);
        serializer = xStreamXmlSerializerBuilder.build();
    }
    
    @Test
    public void shouldRoundTripSerialize() {
        ProvisioningIdentityCertificate cert = ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT;
        
        String xml = serializer.serialize(cert);
        ProvisioningIdentityCertificate deserializedCert = serializer.deserialize(xml);
        
        assertEquals(cert, deserializedCert);        
    }
    
    @Test
    public void shouldProduceSimpleXml() {
        ProvisioningIdentityCertificate cert = ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT;
        String xml = serializer.serialize(cert);
        
        String expectedRegex = "<ProvisioningIdentityCertificate>\n" +
                               "  <encoded>[^<]*</encoded>\n" +
                               "</ProvisioningIdentityCertificate>";

        assertTrue(Pattern.matches(expectedRegex, xml));
    }
    
}
