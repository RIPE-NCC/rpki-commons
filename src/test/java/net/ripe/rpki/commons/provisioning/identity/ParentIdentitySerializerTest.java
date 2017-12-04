/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.provisioning.identity;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
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
                    "<ns0:offer/>\n" +
                    "</ns0:parent_response>";

    public static final ParentIdentity PARENT_IDENTITY = new ParentIdentitySerializer().deserialize(exampleXml);


    @Test
    public void shouldDeserializeXml() {
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        ParentIdentity parentId = serializer.deserialize(exampleXml);
        assertNotNull(parentId);
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
        ProvisioningIdentityCertificate childIdCertificate = ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT_2;
        ParentIdentity parentIdentity = new ParentIdentity(upDownUrl, parentHandle, childHandle, parentIdCertificate, childIdCertificate);

        ParentIdentitySerializer serializer = new ParentIdentitySerializer();


        String xml = serializer.serialize(parentIdentity);

        ParentIdentity deserializedParentId = serializer.deserialize(xml);

        assertEquals(parentIdentity, deserializedParentId);
    }


}
