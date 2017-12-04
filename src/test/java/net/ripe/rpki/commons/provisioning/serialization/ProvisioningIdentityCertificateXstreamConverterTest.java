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
package net.ripe.rpki.commons.provisioning.serialization;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import org.junit.Before;
import org.junit.Test;

import java.util.regex.Pattern;

import static org.junit.Assert.*;


public class ProvisioningIdentityCertificateXstreamConverterTest {

    private XStreamXmlSerializer<ProvisioningIdentityCertificate> serializer;

    @Before
    public void given() {
        XStreamXmlSerializerBuilder<ProvisioningIdentityCertificate> xStreamXmlSerializerBuilder = XStreamXmlSerializerBuilder.newForgivingXmlSerializerBuilder(ProvisioningIdentityCertificate.class);
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
