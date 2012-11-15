/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
