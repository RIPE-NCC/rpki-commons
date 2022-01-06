package net.ripe.rpki.commons.provisioning.identity;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.*;


public class ParentIdentitySerializerTest {

    static final String exampleXml =
            "<ns0:parent_response xmlns:ns0=\"http://www.hactrn.net/uris/rpki/rpki-setup/\" valid_until=\"2012-06-30T04:07:50Z\" service_uri=\"http://localhost:4401/up-down/Alice/Bob\" child_handle=\"Bob\" parent_handle=\"Alice\" version=\"2\" tag=\"1234\">\n" +
                    "<ns0:parent_bpki_ta>\n" +
                    "MIIDJDCCAgygAwIBAgIBATANBgkqhkiG9w0BAQsFADArMSkwJwYDVQQDEyBBbGlj\n" +
                    "ZSBCUEtJIFJlc291cmNlIFRydXN0IEFuY2hvcjAeFw0xMTA3MDEwNDA3MTlaFw0x\n" +
                    "MjA2MzAwNDA3MTlaMCsxKTAnBgNVBAMTIEFsaWNlIEJQS0kgUmVzb3VyY2UgVHJ1\n" +
                    "c3QgQW5jaG9yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0nVOC7Ik\n" +
                    "bc9D3lNPspAp96LEmxqhfWcF70wOk8MHX2skMoHYa3UsyTMOJR4Pv+DRieLbPI8E\n" +
                    "ExrLZRqTrY4+OKRG5sekk3zeIc40g4p8jw6aPxlPUFvJAQdsW+iOYljaPhgWMiGH\n" +
                    "Qm2ZfsXUlvr8XtmkryGbzcaJy2CaAnUi5dwUmpMx7GEcUz+LpJ6tfyB1aF1CpnBm\n" +
                    "pvOhIl+Tlk55Zpo2Nn1Ty0TiTX40fK/ToKZn+/5LkRBKXjGUSWlMyWBVJZVCHo/Z\n" +
                    "PLtPbjUr0gczIYp24q4GxmAHbK12GT/4vGdnQCyadKBDF4Kv0BP6TFf+BP3aE2P7\n" +
                    "biQa919zuZzfCQIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQj\n" +
                    "tovHYOZzUno6MsFjYyKdJZf3NDAfBgNVHSMEGDAWgBQjtovHYOZzUno6MsFjYyKd\n" +
                    "JZf3NDANBgkqhkiG9w0BAQsFAAOCAQEApkybLXSqUGFf6TxVz+AXVbMtTr22tUJ+\n" +
                    "nMocs6lDsyXt2QC/ef3iPTECfJXJrWxCF3PaAWcjV/QQVw3Z2BqblHPmNPM0DxhJ\n" +
                    "OBv065L041zZla4163XSzEzRHJn+99E9jPs15w7if2A1m2XH2W2gg3aSMBSqZXcM\n" +
                    "6Z+W6XsH0dx5c10YspJBSXRls7SsKRpS30fCs2+jSYA0AWvxCTfCNmVf6ssMmAyr\n" +
                    "6Ynrt3fS0MpprBPxJF3KWveHLhaUxLYefSsnsV6o3nfZYwyDlo9m7t3IQCg+Yg7k\n" +
                    "FO2iB8/TDRIdP6bpBvpVrQ13FvWqC6CglZ0fbFRNklotIVxcP1cuNw==\n" +
                    "</ns0:parent_bpki_ta>\n" +
                    "</ns0:parent_response>";


    @Test
    public void shouldDeserializeXml() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        ParentIdentity parentId = serializer.deserialize(exampleXml);
        assertNotNull(parentId);
        assertEquals(1, parentId.getVersion());
        assertEquals("Bob", parentId.getChildHandle());
        assertEquals("Alice", parentId.getParentHandle());
        assertEquals(URI.create("http://localhost:4401/up-down/Alice/Bob"), parentId.getUpDownUrl());

        assertNotNull(parentId.getParentIdCertificate());
    }

    @Test
    public void shouldDoRoundTripSerializeDeserialize() {
        URI upDownUrl = URI.create("http://host/updown");
        String parentHandle = "parent";
        String childHandle = "child";
        ProvisioningIdentityCertificate parentIdCertificate = ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT;
        ParentIdentity parentIdentity = new ParentIdentity(upDownUrl, parentHandle, childHandle, parentIdCertificate);

        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        String xml = serializer.serialize(parentIdentity);

        ParentIdentity deserializedParentId = serializer.deserialize(xml);

        assertEquals(parentIdentity, deserializedParentId);
    }

    @Test
    public void shouldFailToDeserializeInvalidXml() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(IdentitySerializer.IdentitySerializerException.class, () -> {
            serializer.deserialize("NOT VALID");
        });

        assertEquals("Fail to parse parent response", exception.getMessage());
    }

    @Test
    public void shouldFailToDeserializeXmlIfParentResponseIsNotPresent() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(IdentitySerializer.IdentitySerializerException.class, () -> {
            serializer.deserialize("<xml></xml>");
        });

        assertEquals("parent_response element not found", exception.getMessage());
    }

    @Test
    public void shouldFailToDeserializeXmlIfChildHandlerIsNotPresent() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(DomXmlSerializerException.class, () -> {
            serializer.deserialize("<ns0:parent_response xmlns:ns0=\"http://www.hactrn.net/uris/rpki/rpki-setup/\"></ns0:parent_response>" );
        });

        assertEquals("attribute 'child_handle' not found", exception.getMessage());
    }

    @Test
    public void shouldFailToDeserializeXmlIfParentHandlerIsNotPresent() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(DomXmlSerializerException.class, () -> {
            serializer.deserialize("<ns0:parent_response child_handle=\"Bob\" xmlns:ns0=\"http://www.hactrn.net/uris/rpki/rpki-setup/\"></ns0:parent_response>" );
        });

        assertEquals("attribute 'parent_handle' not found", exception.getMessage());
    }

    @Test
    public void shouldFailToDeserializeXmlIfServiceURIIsNotPresent() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(DomXmlSerializerException.class, () -> {
            serializer.deserialize("<ns0:parent_response child_handle=\"Bob\" parent_handle=\"Alice\" xmlns:ns0=\"http://www.hactrn.net/uris/rpki/rpki-setup/\"></ns0:parent_response>" );
        });

        assertEquals("attribute 'service_uri' not found", exception.getMessage());
    }

    @Test
    public void shouldFailToDeserializeXmlIfParentBpkiTaIsNotPresent() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(IdentitySerializer.IdentitySerializerException.class, () -> {
            serializer.deserialize("<ns0:parent_response child_handle=\"Bob\" parent_handle=\"Alice\" service_uri=\"http://localhost:4401/up-down/Alice/Bob\" xmlns:ns0=\"http://www.hactrn.net/uris/rpki/rpki-setup/\"></ns0:parent_response>" );
        });

        assertEquals("parent_bpki_ta element not found", exception.getMessage());
    }

    @Test
    public void shouldFailToDeserializeXmlIfParentBpkiTaIsEmpty() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            serializer.deserialize("<ns0:parent_response child_handle=\"Bob\" parent_handle=\"Alice\" service_uri=\"http://localhost:4401/up-down/Alice/Bob\" xmlns:ns0=\"http://www.hactrn.net/uris/rpki/rpki-setup/\">" +
                    "<ns0:parent_bpki_ta></ns0:parent_bpki_ta>" +
                    "</ns0:parent_response>" );
        });

        assertEquals("Identity Certificate validation failed: [ValidationCheck[key=cert.parsed,params={},status=ERROR]]", exception.getMessage());
    }


}
